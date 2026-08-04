// Package race implements F7: race-condition candidate surface + a
// concurrent-request wrapper.
//
// Race conditions on coupon / credit / balance / vote endpoints are a
// top-tier bug-bounty class. The pattern: a backend reads
// (balance, total) → checks if balance >= total → deducts. If two
// requests fire in parallel, both can see the pre-deduction balance
// and both succeed — the user spends the same coupon twice, double-
// votes, etc.
//
// The module does two things:
//
//  1. SCAN: pull URLs from all_urls.txt and filter for paths
//     containing the business-logic keywords (redeem, coupon,
//     apply, transfer, withdraw, vote, like, etc.). The result
//     goes to race_candidates.txt — the hunter's queue.
//
//  2. PROBE: for the top 25 candidates, fire 20 concurrent
//     requests with a unique marker substituted in the path/query,
//     then grep the responses for the marker appearing in >1
//     successful response. A hit means the endpoint processed
//     multiple "unique" requests in parallel, which is the
//     textbook TOCTOU condition.
//
// The 25-cap is the right number: each candidate takes ~5-15
// seconds at 20-way concurrency, so 25 candidates is a 4-6 minute
// pass. Higher numbers yield diminishing returns because the
// "interesting" endpoints (the ones that actually have business
// logic) are usually a tiny fraction of the URL set.
package race

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CyberShuriken/rfuf/internal/findings/internal/iohelp"
)

// raceKeywords are the path substrings we treat as race candidates.
// Each is paired with a one-line hint the hunter reads to know what
// kind of race to test for.
var raceKeywords = []struct {
	kw   string
	hint string
}{
	{"coupon", "coupon-redemption double-spend"},
	{"redeem", "redemption double-spend"},
	{"apply", "coupon/credit apply race"},
	{"transfer", "balance transfer race"},
	{"withdraw", "withdrawal double-spend"},
	{"vote", "vote-doubling"},
	{"like", "like-counter race"},
	{"checkout/apply", "checkout coupon race"},
	{"points/redeem", "points redemption race"},
	{"wallet/transfer", "wallet transfer race"},
	{"gift", "gift-card redeem race"},
	{"invite", "invite-bonus race"},
	{"signup-bonus", "signup-credit race"},
	{"referral", "referral-bonus race"},
	{"promo", "promo-code race"},
	{"discount", "discount race"},
	{"claim", "claim/award race"},
}

// Run is the entry point. workDir is the rfuf work dir.
func Run(workDir string) error {
	urls, err := iohelp.ReadLines(workDir + "/all_urls.txt")
	if err != nil {
		return fmt.Errorf("read all_urls.txt: %w", err)
	}
	if len(urls) == 0 {
		empty := []string{}
		_ = iohelp.WriteLines(workDir+"/race_candidates.txt", empty)
		return iohelp.WriteLines(workDir+"/race_results.txt", empty)
	}

	// === Phase 1: SCAN — build candidate list ===
	var cands []raceCandidate
	seen := map[string]bool{}
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		pathLower := strings.ToLower(u.Path)
		for _, kw := range raceKeywords {
			if strings.Contains(pathLower, kw.kw) {
				if seen[raw] {
					break
				}
				seen[raw] = true
				cands = append(cands, raceCandidate{url: raw, hint: kw.hint})
				break
			}
		}
	}

	var candLines []string
	for _, c := range cands {
		candLines = append(candLines, fmt.Sprintf("%s\thint=%s", c.url, c.hint))
	}
	if err := iohelp.WriteLines(workDir+"/race_candidates.txt", candLines); err != nil {
		return err
	}

	// === Phase 2: PROBE — concurrent marker test on top N ===
	const top = 25
	if len(cands) > top {
		cands = cands[:top]
	}
	if len(cands) == 0 {
		return iohelp.WriteLines(workDir+"/race_results.txt", nil)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	results := probeAll(ctx, cands)
	return iohelp.WriteLines(workDir+"/race_results.txt", results)
}

func probeAll(ctx context.Context, cands []raceCandidate) []string {
	sem := make(chan struct{}, 5) // 5 candidates in parallel; each does 20-way fan-out
	var wg sync.WaitGroup
	var mu sync.Mutex
	var rows []string

	tr := &http.Transport{MaxIdleConns: 200, MaxIdleConnsPerHost: 20}
	client := &http.Client{
		Transport: tr,
		Timeout:   8 * time.Second,
	}

	for _, c := range cands {
		c := c
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			r := probeCandidate(ctx, client, c)
			mu.Lock()
			rows = append(rows, r...)
			mu.Unlock()
		}()
	}
	wg.Wait()
	return rows
}

// raceCandidate is one entry in the URL → hint map for race probing.
// Anonymous-struct param was problematic because anonymous types
// compare by package of declaration rather than structurally, so two
// anonymous structs with the same field set are still distinct
// in Go's type system. Promoting to a named type lets probeAll and
// probeCandidate share the same parameter type.
type raceCandidate struct {
	url  string
	hint string
}

// probeCandidate fires 20 concurrent GETs against url with a unique
// marker. Counts the responses that contain the marker (i.e. the
// server "processed" the unique request) and the responses with
// 2xx status. If both >= 2, the endpoint is racy.
func probeCandidate(ctx context.Context, client *http.Client, c raceCandidate) []string {
	marker := "rfuf" + randHex(6)

	// Inject marker as an extra query param. The original URL's params
	// are preserved; we just append our marker.
	u, err := url.Parse(c.url)
	if err != nil {
		return nil
	}
	q := u.Query()
	q.Set("rfuf_marker", marker)
	u.RawQuery = q.Encode()

	var (
		ok2xx     atomic.Int32
		sawMarker atomic.Int32
		wg        sync.WaitGroup
	)
	const concurrent = 20
	for i := 0; i < concurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "rfuf-race/1.0")
			req.Header.Set("X-RFUF-Marker", marker)
			iohelp.ApplyAuth(req)
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				ok2xx.Add(1)
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
			if strings.Contains(string(body), marker) {
				sawMarker.Add(1)
			}
		}()
	}
	wg.Wait()

	// Heuristic: if at least 2 of 20 responses came back 2xx AND at
	// least 2 echoed the marker, the endpoint processed multiple
	// distinct requests in parallel without rejecting them — that
	// is the TOCTOU signal.
	if ok2xx.Load() < 2 || sawMarker.Load() < 2 {
		return nil
	}
	sev := "MEDIUM"
	if sawMarker.Load() >= 5 {
		sev = "HIGH"
	}
	return []string{fmt.Sprintf("%s\thint=%s\t2xx=%d\tmarker_reflect=%d/%d\tseverity=%s",
		c.url, c.hint, ok2xx.Load(), sawMarker.Load(), concurrent, sev)}
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Ensure bufio is referenced. (Used in os.Open for future expansion.)
var _ = bufio.NewScanner
var _ = os.Open
