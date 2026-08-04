// Package filter implements the URL testability filter that decides whether
// a URL is worth feeding to a vuln scanner. The previous pipeline emitted
// target lists like 1208 entries for SQLi when most of them were static
// .html files, Discourse public forum URLs, or analytics-tracking params
// that never reach a backend sink — so sqlmap and nuclei ran for hours
// against junk and reported 0 bugs.
//
// IsTestableURL is the single source of truth for the new pipeline: it
// rejects static assets, analytics/UTM params, Discourse public forum paths,
// and paths without a query parameter. The remaining URLs are the ones
// nuclei/dalfox/sqlmap can actually probe for injection or fuzz.
package filter

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// Pre-compiled patterns. Compiled once at package init so per-URL calls
// are a sub-microsecond regex match.
var (
	// Static asset paths. The negative lookbehind `[^?&]` ensures we only
	// match when the extension is in the path part, not the query string
	// value. Go's regexp package (RE2) does NOT support lookbehind, so we
	// instead match the entire path component before any '?' and check the
	// extension there. Only the path is checked.
	pathStaticAsset = regexp.MustCompile(`\.(html?|css|js|json|xml|pdf|jpg|jpeg|png|gif|svg|ico|woff2?|ttf|map|mp4|mp3|webp)(?:[#/?]|$)`)

	// Analytics / tracking parameters that never reach a backend sink.
	// Covers HubSpot (__hs*), Google Analytics (_gl, _ga, _hsmi), UTM,
	// Facebook (fbclid, fbp), Marketo, Matomo, and similar.
	analyticsParam = regexp.MustCompile(`[?&](_gl|_ga|_hsmi|_hsenc|_hsfp|__hs\w+|utm_\w+|fbclid|gclid|fbp|gtm|matomo_\w+|hsa_acc|hsCtaTracking)=`)

	// Discourse public forum path segments. These are public read-only URLs
	// the IDOR/RCE/redirect/LFI scanners cannot test because they're not
	// authenticated endpoints and don't accept request params that map to
	// a backend resource. Stripped from the IDOR/redirect target lists.
	//
	// Anchored to URL path with leading slash, ending at path boundary or
	// end of string. The list is intentionally narrow — we only exclude
	// URL prefixes that are KNOWN to be public read-only.
	discoursePublicPath = regexp.MustCompile(`/(t/|c/|tag/|latest|opensearch\.xml|robots\.txt|sitemap[.a-z]*|raw/|assets/|javascripts/|stylesheets/|plugins/|images/|svg-icons/|letter_avatar/|user_avatar/|badges/u)`)

	// Fuzzable value: matches a query parameter with a value of 1-200 chars.
	// We reject URLs that have a parameter name but no value (?foo with no =)
	// because sqlmap/nuclei can't test what isn't there.
	fuzzableValue = regexp.MustCompile(`[?&]\w+=[^&]{1,200}($|&)`)
)

// Result is the classification produced by IsTestableURL. The Reason field
// is empty for pass-through URLs and a short string for rejection so the
// caller can produce a transparent "what was filtered out" report.
type Result struct {
	URL    string
	Pass   bool
	Reason string
}

// IsTestableURL returns true if the URL has a query parameter whose value
// is a fuzzable backend sink — not an analytics token, not a static asset,
// not a Discourse public forum URL. The two-pass design rejects on first
// fail so the function is short-circuiting instead of always evaluating.
//
// Rejection reasons (in order of evaluation):
//  1. "static asset"  — extension matches .html/.js/.css/etc.
//  2. "no query param" — no '?' in URL at all
//  3. "no fuzzable value" — has '?' but no key=value with a value
//  4. "analytics param" — only analytics/UTM/tracking params
//  5. "discourse public path" — /c/, /t/, /tag/, etc.
func IsTestableURL(u string) bool {
	_, ok := ClassifyURL(u)
	return ok
}

// ClassifyURL is the same as IsTestableURL but returns the rejection reason
// for forensic reporting. Used by the pipeline's "what was filtered out"
// writer so the hunter can see *why* a candidate was excluded.
func ClassifyURL(u string) (Result, bool) {
	// Static-asset check is path-only so query param values like
	// `file=report.pdf` don't trip the filter.
	if pathStaticAsset.MatchString(pathOnly(u)) {
		return Result{URL: u, Pass: false, Reason: "static asset"}, false
	}
	if !strings.Contains(u, "?") {
		return Result{URL: u, Pass: false, Reason: "no query param"}, false
	}
	if !fuzzableValue.MatchString(u) {
		return Result{URL: u, Pass: false, Reason: "no fuzzable value"}, false
	}
	if analyticsParam.MatchString(u) {
		return Result{URL: u, Pass: false, Reason: "analytics param only"}, false
	}
	if discoursePublicPath.MatchString(u) {
		return Result{URL: u, Pass: false, Reason: "discourse public path"}, false
	}
	return Result{URL: u, Pass: true}, true
}

// pathOnly returns the URL without the query string and fragment. Used
// for static-asset detection so a value like `file=report.pdf` is not
// mistaken for a path ending in `.pdf`.
func pathOnly(u string) string {
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		return u[:i]
	}
	return u
}

// FilterURLs reads URLs from in (one per line), writes pass-through URLs
// to out, and returns the per-reason drop counts. Lines that fail
// ClassifyURL are dropped (with their rejection reason logged via the
// returned counters). Blank lines are skipped silently.
//
// The reader is consumed to EOF; the caller is responsible for closing it.
func FilterURLs(in io.Reader, out io.Writer) (dropped map[string]int, totalIn, totalOut int, err error) {
	scanner := bufio.NewScanner(in)
	// Allow long lines (some URLs exceed the default 64 KiB scanner buffer).
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	writer := bufio.NewWriter(out)
	defer writer.Flush()

	dropped = make(map[string]int)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		totalIn++
		r, ok := ClassifyURL(line)
		if !ok {
			dropped[r.Reason]++
			continue
		}
		if _, err := writer.WriteString(line + "\n"); err != nil {
			return dropped, totalIn, totalOut, fmt.Errorf("write pass-through: %w", err)
		}
		totalOut++
	}
	if err := scanner.Err(); err != nil {
		return dropped, totalIn, totalOut, err
	}
	return dropped, totalIn, totalOut, nil
}

// FilterFile is a convenience wrapper around FilterURLs that opens paths
// on disk. Returns the same counters.
func FilterFile(inPath, outPath string) (map[string]int, int, int, error) {
	in, err := os.Open(inPath)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("open input: %w", err)
	}
	defer in.Close()
	out, err := os.Create(outPath)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("create output: %w", err)
	}
	defer out.Close()
	return FilterURLs(in, out)
}
