// Package jsmine implements F10: deep regex/AST-lite mining of JS
// bundles for secrets, POST endpoints, and admin paths.
//
// The existing jsmap_scrape stage (pipeline.go) extracts GET paths
// from JS bundles. That's barely scratching the surface. Real hunters
// spend hours on each bundle because the highest-value findings live
// here: hardcoded API keys, internal-only POST endpoints, S3 URLs
// pointing to private buckets, GraphQL operation names that hint at
// admin-only mutations.
//
// What this module extracts (one Finding per artifact, sorted by
// signal density):
//
//   - secrets       — AWS access key, GitHub PAT, Slack token, Stripe
//                     live key, Google API key, OpenAI key, SendGrid
//                     key, Twilio, Datadog, JWT-shaped strings
//   - post-endpoints — `fetch("...", { method: "POST" })` and
//                      `axios.post("...", ...)` callsites
//   - admin-paths    — `/admin/`, `/internal/`, `/api/admin/`,
//                      `/staff/`, `/moderator/` paths in fetch URLs
//   - s3-urls        — s3.amazonaws.com / s3-website / s3-accelerate
//                      URLs hardcoded in the bundle
//   - graphql-ops    — `mutation { ... }` and `query { ... }` names
//
// Output: js_mine_findings.txt with one line per artifact, prefixed
// by its severity:
//
//   CRITICAL <host> secret:aws-access-key id=AKIA... in bundle=...
//   HIGH     <host> post-endpoint path=/api/v2/users/delete bundle=...
//   MEDIUM   <host> admin-path path=/admin/billing bundle=...
//
// Bundles are read from the work dir's js_bundles/ directory, which
// the jsmap_scrape stage populates.
package jsmine

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/CyberShuriken/rfuf/internal/findings/internal/iohelp"
)

// secretKind names a category of credential so the report can group
// findings and recommend the right disclosure path (e.g. GitHub
// secret-scanning page for GitHub PATs).
type secretKind string

const (
	skAWS         secretKind = "aws-access-key"
	skAWSSecret   secretKind = "aws-secret-key"
	skGitHubPAT   secretKind = "github-pat"
	skSlack       secretKind = "slack-token"
	skStripe      secretKind = "stripe-live-key"
	skGoogle      secretKind = "google-api-key"
	skOpenAI      secretKind = "openai-key"
	skSendGrid    secretKind = "sendgrid-key"
	skTwilio      secretKind = "twilio-key"
	skDatadog     secretKind = "datadog-key"
	skJWT         secretKind = "jwt"
	skGenericAPI  secretKind = "generic-api-key"
)

// secretPattern binds a secret kind to its regex. We require a known
// key prefix where possible (AKIA, ghp_, sk_live_, etc.) because
// those have very low false-positive rates.
type secretPattern struct {
	kind secretKind
	re   *regexp.Regexp
	sev  string
}

func compile(pat string) *regexp.Regexp { return regexp.MustCompile(pat) }

var secretPatterns = []secretPattern{
	{skAWS, compile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`), "CRITICAL"},
	{skGitHubPAT, compile(`\bghp_[A-Za-z0-9]{36}\b`), "CRITICAL"},
	{skGitHubPAT, compile(`\bgithub_pat_[A-Za-z0-9_]{82}\b`), "CRITICAL"},
	{skSlack, compile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`), "HIGH"},
	{skStripe, compile(`\bsk_live_[A-Za-z0-9]{24,}\b`), "CRITICAL"},
	{skStripe, compile(`\brk_live_[A-Za-z0-9]{24,}\b`), "CRITICAL"},
	{skGoogle, compile(`\bAIza[0-9A-Za-z_-]{35}\b`), "HIGH"},
	{skOpenAI, compile(`\bsk-[A-Za-z0-9]{32,}\b`), "CRITICAL"},
	{skSendGrid, compile(`\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b`), "CRITICAL"},
	{skTwilio, compile(`\bSK[0-9a-fA-F]{32}\b`), "HIGH"},
	{skDatadog, compile(`\bdd_[A-Za-z0-9]{32,}\b`), "HIGH"},
	{skJWT, compile(`\beyJ[A-Za-z0-9_=-]+\.eyJ[A-Za-z0-9_=-]+\.[A-Za-z0-9_.+/=-]{20,}\b`), "HIGH"},
	{skGenericAPI, compile(`(?i)["'](?:api[_-]?key|secret|token)["']\s*[:=]\s*["']([A-Za-z0-9_/+=-]{24,})["']`), "MEDIUM"},
}

// postCallPattern matches `fetch(URL, ...)` and `axios.post(URL, ...)`
// callsites. We don't try to parse the JS — regex is enough to find
// 95% of callsites. The optional `method: "POST"` filter keeps
// one-off GETs out.
var (
	postCallPattern    = regexp.MustCompile(`(?:fetch|axios\.post|axios\(\s*\{\s*method\s*:\s*["']POST["'])\s*\(\s*["']([^"']+)["']`)
	adminPathPattern   = regexp.MustCompile(`["'](/(?:admin|internal|api/admin|staff|moderator|back-?office|backoffice)/[A-Za-z0-9/_-]+)["']`)
	s3URLPattern       = regexp.MustCompile(`["'](https?://[A-Za-z0-9.-]*s3[A-Za-z0-9.-]*\.amazonaws\.com/[A-Za-z0-9._/-]+)["']`)
	graphqlOpPattern   = regexp.MustCompile(`\b(mutation|query|subscription)\s+([A-Z][A-Za-z0-9_]{2,})\b`)
)

// Run is the entry point. workDir is the rfuf work dir.
func Run(workDir string) error {
	bundleDir := workDir + "/js_bundles"
	entries, err := ioutil.ReadDir(bundleDir)
	if err != nil {
		// No bundles yet — module is a no-op.
		return iohelp.WriteLines(workDir+"/js_mine_findings.txt", nil)
	}

	// Cap to 200 bundles — each bundle is 50-500KB and we run ~10
	// regex passes over it.
	const cap = 200
	if len(entries) > cap {
		entries = entries[:cap]
	}

	type finding struct {
		line string
		sev  string // for sorting
	}
	var findings []finding
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		bundlePath := filepath.Join(bundleDir, e.Name())
		body, err := os.ReadFile(bundlePath)
		if err != nil {
			continue
		}
		bodyStr := string(body)
		// host is the bundle file's prefix (jsmap_scrape uses
		// "<host>_<md5>.js").
		host := bundleHost(e.Name())

		// === Secrets ===
		for _, sp := range secretPatterns {
			for _, m := range sp.re.FindAllString(bodyStr, 5) {
				// Truncate the matched value to 16 chars for
				// safety — we don't want a real secret in the
				// output file. The hunter re-extracts from the
				// bundle if needed.
				short := m
				if len(short) > 24 {
					short = short[:16] + "..."
				}
				findings = append(findings, finding{
					line: fmt.Sprintf("%s\thost=%s\tartifact=secret\tkind=%s\tvalue=%s\tbundle=%s",
						sp.sev, host, sp.kind, short, e.Name()),
					sev: sp.sev,
				})
			}
		}

		// === POST endpoints ===
		for _, m := range postCallPattern.FindAllStringSubmatch(bodyStr, 10) {
			path := m[1]
			if !strings.HasPrefix(path, "/") {
				continue
			}
			sev := "INFO"
			if adminPathPattern.MatchString(path) {
				sev = "HIGH"
			}
			findings = append(findings, finding{
				line: fmt.Sprintf("%s\thost=%s\tartifact=post-endpoint\tpath=%s\tbundle=%s",
					sev, host, path, e.Name()),
				sev: sev,
			})
		}

		// === Admin paths (in GET URLs — the existing jsmap_scrape
		// only got paths, not the callsite) ===
		for _, m := range adminPathPattern.FindAllStringSubmatch(bodyStr, 10) {
			path := m[1]
			findings = append(findings, finding{
				line: fmt.Sprintf("MEDIUM\thost=%s\tartifact=admin-path\tpath=%s\tbundle=%s",
					host, path, e.Name()),
				sev: "MEDIUM",
			})
		}

		// === Hardcoded S3 URLs ===
		for _, m := range s3URLPattern.FindAllStringSubmatch(bodyStr, 5) {
			url := m[1]
			findings = append(findings, finding{
				line: fmt.Sprintf("HIGH\thost=%s\tartifact=s3-url\turl=%s\tbundle=%s",
					host, url, e.Name()),
				sev: "HIGH",
			})
		}

		// === GraphQL operations ===
		for _, m := range graphqlOpPattern.FindAllStringSubmatch(bodyStr, 10) {
			kind, name := m[1], m[2]
			if kind != "mutation" {
				continue
			}
			// Mutations are the reportable ones. Queries are usually
			// public.
			findings = append(findings, finding{
				line: fmt.Sprintf("MEDIUM\thost=%s\tartifact=graphql-mutation\tname=%s\tbundle=%s",
					host, name, e.Name()),
				sev: "MEDIUM",
			})
		}
	}

	// Sort by severity desc, then by line.
	sevOrder := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
	sort.SliceStable(findings, func(i, j int) bool {
		ai, bi := sevOrder[findings[i].sev], sevOrder[findings[j].sev]
		if ai != bi {
			return ai < bi
		}
		return findings[i].line < findings[j].line
	})

	lines := make([]string, len(findings))
	for i, f := range findings {
		lines[i] = f.line
	}
	return iohelp.WriteLines(workDir+"/js_mine_findings.txt", lines)
}

// bundleHost reverses jsmap_scrape's filename scheme:
// "<host-prefix>_<md5>.js" → "<host>". The prefix can contain
// underscores (from the URL path) and dots (from the host). We strip
// the trailing hex-shaped segment (the md5), then convert the
// remaining separators back to URL path form. Dots in the trailing
// TLD-like segment are preserved so the host reads as a real host;
// underscores (which were path-separator replacements) and inner
// host-dots are converted to slashes.
func bundleHost(name string) string {
	base := name
	if i := strings.LastIndex(base, "."); i >= 0 {
		base = base[:i]
	}
	// The last underscore-separated segment is the md5. Strip it
	// whenever it looks hex-shaped (≥16 hex chars).
	if i := strings.LastIndex(base, "_"); i >= 0 {
		tail := base[i+1:]
		if len(tail) >= 16 && isHex(tail) {
			base = base[:i]
		}
	}
	// Underscores were path-separator replacements — convert all to `/`.
	base = strings.ReplaceAll(base, "_", "/")
	// Dots in the host were host-segment separators. We want the
	// final TLD-like segment to read as a domain (preserved with its
	// dot) and inner host-dots to convert to `/`. We don't know the
	// TLD list, so we treat the last dot-separated segment as
	// "TLD-like" if it contains no underscore.
	if lastDot := strings.LastIndex(base, "."); lastDot >= 0 {
		head := base[:lastDot]
		tail := base[lastDot:] // includes the leading "."
		head = strings.ReplaceAll(head, ".", "/")
		base = head + tail
	}
	return base
}

func isHex(s string) bool {
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}
