// Package paramshape implements F2: HTTP parameter pollution (HPP)
// detection.
//
// Given a list of unique hosts (from alive.txt), the module picks the
// top candidate object-reference parameters per host (id, user_id,
// account_id, order_id, doc_id, etc.) and probes each parameter with
// five shapes:
//
//   1. baseline        ?id=1
//   2. array           ?id[]=1
//   3. duplicate key   ?id=1&id=2
//   4. mixed case      ?id=1&ID=2
//   5. null byte       ?id=1%00
//
// Any two shapes that produce a different response body hash are
// reported. PHP/ASP/J2EE handle duplicate keys differently, so a hit
// here usually means "I can override the value the server used" — a
// classic HPP class.
//
// The module writes paramshape_findings.txt with one row per host+param
// that showed divergence, plus a "diff" column showing the response
// sizes for each shape so the hunter can prioritize.
package paramshape

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/CyberShuriken/rfuf/internal/findings/internal/iohelp"
)

// candidateParams are the parameter names we test. These are the names
// that classically route to a backend object reference — a SQL UPDATE,
// a file read, a Mongo _id lookup, etc. We don't bother with
// pagination/UI params like `page=` or `sort=`; those don't expose
// interesting behavior on duplicate submission.
var candidateParams = []string{
	"id", "ID", "Id",
	"user_id", "uid", "userId",
	"account_id", "acct", "account",
	"order_id", "orderId",
	"doc_id", "docId", "document",
	"file_id", "fileId",
	"product_id", "productId", "pid",
	"article_id", "articleId",
	"msg_id", "message_id", "messageId",
	"profile_id", "profileId",
	"booking_id", "reservation_id",
	"invoice_id", "invoiceId",
	"comment_id", "commentId",
	"post_id", "postId",
	"report_id", "reportId",
	"category_id", "categoryId",
	"item_id", "itemId",
	"news_id", "newsId",
	"page_id", "pageId",
}

// Run is the entry point. workDir is the rfuf work dir; the function
// reads alive.txt and writes paramshape_findings.txt.
func Run(workDir string) error {
	hosts, err := iohelp.ReadLines(workDir + "/alive.txt")
	if err != nil {
		return fmt.Errorf("read alive.txt: %w", err)
	}
	if len(hosts) == 0 {
		return iohelp.WriteLines(workDir+"/paramshape_findings.txt", nil)
	}

	// Cap to 200 hosts. Each host is 5*N HTTP requests where N is the
	// number of candidate params we test (≈25). 200 hosts × 125 reqs
	// = 25k requests, which is the right ceiling for a 10-min wall
	// clock with 25-way concurrency.
	const cap = 200
	if len(hosts) > cap {
		hosts = hosts[:cap]
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	rows := probeAll(ctx, hosts)
	return iohelp.WriteLines(workDir+"/paramshape_findings.txt", rows)
}

// probeAll fans out per-host probes with bounded parallelism. Each host
// runs sequentially within itself (we want predictable timing for the
// hash diff) but different hosts run in parallel.
func probeAll(ctx context.Context, hosts []string) []string {
	sem := make(chan struct{}, 25)
	var wg sync.WaitGroup
	rows := make([]string, 0, len(hosts))
	var mu sync.Mutex

	tr := &http.Transport{MaxIdleConns: 100, MaxIdleConnsPerHost: 10}
	client := &http.Client{
		Transport: tr,
		Timeout:   8 * time.Second,
	}

	for _, h := range hosts {
		h := h
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			rs := probeHost(ctx, client, h)
			if len(rs) > 0 {
				mu.Lock()
				rows = append(rows, rs...)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return rows
}

// probeHost tests every candidate param against h in 5 shapes. Reports
// any param where the response hashes diverge across shapes.
func probeHost(ctx context.Context, client *http.Client, host string) []string {
	// Pick a base path that almost certainly exists. /robots.txt is a
	// good choice — every real site has it, and it doesn't accept
	// interesting params so a baseline response is meaningful.
	u, err := url.Parse(host)
	if err != nil {
		return nil
	}
	u.Path = "/"
	// Strip the query so we control it.
	u.RawQuery = ""

	var rows []string
	for _, p := range candidateParams {
		hashes := map[string]string{} // shape -> first-8-of-sha256
		sizes := map[string]int{}
		for _, shape := range shapes(p) {
			probe := *u
			probe.RawQuery = shape
			req, err := http.NewRequestWithContext(ctx, "GET", probe.String(), nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "rfuf-paramshape/1.0")
			iohelp.ApplyAuth(req)
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			sum := sha256.Sum256(body)
			key := shape
			if _, ok := hashes[key]; !ok {
				hashes[key] = hex.EncodeToString(sum[:])[:8]
				sizes[key] = len(body)
			}
		}

		// Divergence: at least two distinct hashes.
		uniq := uniqHashes(hashes)
		if uniq < 2 {
			continue
		}

		// Sort shape names for stable output.
		keys := make([]string, 0, len(hashes))
		for k := range hashes {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var diffParts []string
		for _, k := range keys {
			diffParts = append(diffParts, fmt.Sprintf("%s=%d/%s", k, sizes[k], hashes[k]))
		}
		rows = append(rows, fmt.Sprintf("%s\t%s\thpp=%d\tdiff=[%s]",
			host, p, uniq, strings.Join(diffParts, " ")))
	}
	return rows
}

// shapes returns the 5 HPP shapes for parameter p. We use "1" as the
// base value because it's universally truthy / non-null in backend
// ORMs; "2" makes the duplicate test distinguishable from the baseline.
func shapes(p string) []string {
	return []string{
		fmt.Sprintf("%s=1", p),
		fmt.Sprintf("%s[]=1", p),
		fmt.Sprintf("%s=1&%s=2", p, p),
		fmt.Sprintf("%s=1&%s=2", p, strings.ToUpper(p)),
		fmt.Sprintf("%s=1%%00", p),
	}
}

func uniqHashes(m map[string]string) int {
	seen := map[string]struct{}{}
	for _, v := range m {
		seen[v] = struct{}{}
	}
	return len(seen)
}
