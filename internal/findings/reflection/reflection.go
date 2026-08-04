// Package reflection implements F1: per-URL reflection-site classification.
//
// Given all_urls_200.txt (the set of URLs that responded with a testable
// status code), each module re-fetches the URL with a unique marker
// substituted into every query parameter, then classifies the response
// into one of:
//
//   - html-body       — marker rendered between tags → XSS class
//   - attr-quoted     — marker in attribute value (still XSS-class
//                       for dalfox with quote-breaker payloads)
//   - attr-unquoted   — marker in unquoted attribute → easy XSS
//   - json-value      — marker in JSON response value → scan for
//                       JSON injection / prototype pollution
//   - none            — not reflected (skip)
//
// The output is reflection_findings.txt with tab-separated
// `url<TAB>site<TAB>marker<TAB>param`. dalfox and the report generator
// consume this directly.
//
// Note: this module issues HTTP requests itself rather than shelling
// out to curl. The existing executor path is bash-only; for
// marker-injection logic Go is cleaner than juggling sed/awk. The
// pipeline wrapper is `go run ./internal/findings/reflection` which
// the executor times out exactly like any other stage.
package reflection

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/CyberShuriken/rfuf/internal/findings/internal/iohelp"
)

// Site is the reflection-site classification. Ordered roughly by
// "how useful to a hunter" — html-body and attr-unquoted are
// practically XSS-confirmed, json-value is reportable but harder.
type Site string

const (
	SiteHTMLBody     Site = "html-body"
	SiteAttrQuoted   Site = "attr-quoted"
	SiteAttrUnquoted Site = "attr-unquoted"
	SiteJSONValue    Site = "json-value"
	SiteNone         Site = "none"
)

// Finding is one row in reflection_findings.txt.
type Finding struct {
	URL    string
	Site   Site
	Param  string
	Marker string
}

// line serializes a Finding as the tab-separated line the report
// generator expects.
func (f Finding) line() string {
	return strings.Join([]string{f.URL, string(f.Site), f.Marker, f.Param}, "\t")
}

// Run is the entry point. workDir is the rfuf work dir; the function
// reads all_urls_200.txt and writes reflection_findings.txt. The
// pipeline wrapper is `go run ./internal/findings/reflection <workdir>`.
func Run(workDir string) error {
	urls, err := iohelp.ReadLines(workDir + "/all_urls_200.txt")
	if err != nil {
		return fmt.Errorf("read all_urls_200.txt: %w", err)
	}
	if len(urls) == 0 {
		// Empty input → empty output. Write a 0-byte file so the
		// summary generator's "did the stage run?" check still passes.
		return iohelp.WriteLines(workDir+"/reflection_findings.txt", nil)
	}

	// Cap the per-run URL set. Reflection probing is one HTTP request
	// per URL plus another per *parameter* — for a host with 50 params
	// in the URL that's 50 requests, times the number of hosts. We cap
	// at 1500 to keep runtime bounded on large targets.
	const cap = 1500
	if len(urls) > cap {
		urls = urls[:cap]
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	findings := probeAll(ctx, urls)
	lines := make([]string, len(findings))
	for i, f := range findings {
		lines[i] = f.line()
	}
	return iohelp.WriteLines(workDir+"/reflection_findings.txt", lines)
}

// probeAll fans out HTTP requests with bounded parallelism. 25 in-flight
// is a good middle ground — high enough to finish 1500 URLs in ~2 min
// on a real target, low enough not to trip rate limits on shared hosts.
func probeAll(ctx context.Context, urls []string) []Finding {
	sem := make(chan struct{}, 25)
	var wg sync.WaitGroup
	out := make([]Finding, 0, len(urls))
	var mu sync.Mutex

	tr := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 5,
		IdleConnTimeout:     30 * time.Second,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
		// Don't follow redirects — we want to see the *raw* response
		// body for the marker.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, raw := range urls {
		raw := raw
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			fs := probeURL(ctx, client, raw)
			if len(fs) > 0 {
				mu.Lock()
				out = append(out, fs...)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return out
}

// probeURL takes a single URL, iterates over its query parameters, and
// returns a Finding for every parameter that reflects the marker in the
// response body. We use a unique marker per URL so concurrent
// reflections from the same host don't cross-contaminate.
func probeURL(ctx context.Context, client *http.Client, rawURL string) []Finding {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	q := u.Query()
	if len(q) == 0 {
		return nil
	}

	marker := "rfuf" + randHex(8)

	// Build a probe URL by substituting the marker into every parameter
	// value. We preserve the rest of the URL exactly.
	probe := *u
	pq := url.Values{}
	for k, vs := range q {
		new := make([]string, len(vs))
		for i := range vs {
			new[i] = marker
		}
		pq[k] = new
	}
	probe.RawQuery = pq.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", probe.String(), nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "rfuf-reflection/1.0")
	iohelp.ApplyAuth(req)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	// 1MB cap is plenty for the reflection site check; larger pages
	// almost always have the marker in the first 50KB.
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	bodyStr := string(body)

	var out []Finding
	for k := range q {
		idx := strings.Index(bodyStr, marker)
		if idx < 0 {
			continue
		}
		site := classify(bodyStr, idx, len(marker))
		if site == SiteNone {
			continue
		}
		out = append(out, Finding{
			URL:    rawURL,
			Site:   site,
			Param:  k,
			Marker: marker,
		})
	}
	return out
}

// classify picks a Site based on the characters surrounding the marker
// in the response body. The rules:
//
//   - Surrounded by `<` and `>` or directly inside `<tag>...</tag>`:
//     html-body
//   - Inside an attribute with a quote char on each side: attr-quoted
//   - Inside an attribute with no surrounding quote: attr-unquoted
//   - Body parses as JSON and marker is in a string value: json-value
//   - Otherwise: none
//
// We do the cheap checks first and only fall back to JSON detection
// when nothing else matched.
func classify(body string, idx, markerLen int) Site {
	// Look at a 200-char window around the marker — enough to see
	// surrounding tag/attribute context, small enough to stay cheap.
	win := 200
	lo := idx - win
	if lo < 0 {
		lo = 0
	}
	hi := idx + markerLen + win
	if hi > len(body) {
		hi = len(body)
	}
	snippet := body[lo:hi]

	// JSON value: simple brace/quote heuristic — `{` before and either
	// `}` after or `,` and `"`. Check this BEFORE the quoted-attr check
	// because a JSON string is structurally identical to a quoted
	// attribute value and would otherwise misclassify.
	if isJSONValue(snippet, idx-lo, markerLen) {
		return SiteJSONValue
	}
	// Unquoted attribute: marker preceded by whitespace and `=` with no
	// quote, OR marker is the only thing between `=` and a space/>.
	// Pattern: ` attr=marker` (no surrounding quote).
	if isUnquotedAttr(snippet, idx-lo) {
		return SiteAttrUnquoted
	}
	// Quoted attribute: marker between two quote chars within the
	// snippet.
	if isQuotedAttr(snippet, idx-lo, markerLen) {
		return SiteAttrQuoted
	}
	// HTML body: marker between `>` and `<` (i.e. not inside a tag).
	if isHTMLBody(snippet, idx-lo) {
		return SiteHTMLBody
	}
	return SiteNone
}

func isUnquotedAttr(snippet string, relIdx int) bool {
	// Walk back to find `=`. If we hit a quote first, it's not
	// unquoted. If we hit `<` without finding `=`, also not.
	for i := relIdx - 1; i >= 0 && i >= relIdx-60; i-- {
		c := snippet[i]
		if c == '"' || c == '\'' {
			return false
		}
		if c == '=' {
			return true
		}
		if c == '<' {
			return false
		}
	}
	return false
}

func isQuotedAttr(snippet string, relIdx, markerLen int) bool {
	// Walk left to a quote; walk right to a quote. Both must be the
	// same char and the walk must be short (< 60 chars).
	after := relIdx + markerLen
	if after >= len(snippet) {
		return false
	}
	rq := byte(0)
	for i := after; i < len(snippet) && i < after+60; i++ {
		c := snippet[i]
		if c == '"' || c == '\'' {
			rq = c
			break
		}
		if c == '<' || c == '>' {
			return false
		}
	}
	if rq == 0 {
		return false
	}
	for i := relIdx - 1; i >= 0 && i >= relIdx-60; i-- {
		c := snippet[i]
		if c == rq {
			return true
		}
		if c == '<' || c == '>' || c == ' ' {
			return false
		}
	}
	return false
}

func isHTMLBody(snippet string, relIdx int) bool {
	// Find the nearest `>` and `<` to the left of the marker. If `>`
	// is closer, we're in body. If `<` is closer and not part of a
	// tag we're inside, we're in an attribute.
	closestGT, closestLT := -1, -1
	for i := relIdx - 1; i >= 0 && i >= relIdx-200; i-- {
		if snippet[i] == '>' && closestGT < 0 {
			closestGT = i
			break
		}
	}
	for i := relIdx - 1; i >= 0 && i >= relIdx-200; i-- {
		if snippet[i] == '<' && closestLT < 0 {
			closestLT = i
			break
		}
	}
	if closestGT < 0 {
		return false
	}
	if closestLT < 0 || closestGT > closestLT {
		return true
	}
	return false
}

func isJSONValue(snippet string, relIdx, markerLen int) bool {
	// Look for a `{` to the left within 100 chars and either `,` or
	// `}` to the right within 100 chars. Very rough, but good enough
	// to flag "this looks like JSON" so the report generator can list
	// it for manual review.
	hasBrace := false
	for i := relIdx - 1; i >= 0 && i >= relIdx-100; i-- {
		if snippet[i] == '{' {
			hasBrace = true
			break
		}
	}
	if !hasBrace {
		return false
	}
	after := relIdx + markerLen
	for i := after; i < len(snippet) && i < after+100; i++ {
		c := snippet[i]
		if c == '}' || c == ',' {
			return true
		}
		if c == '<' {
			return false
		}
	}
	return false
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
