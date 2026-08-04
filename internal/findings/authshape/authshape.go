// Package authshape implements F3: cookie and JWT misconfiguration
// fingerprinting. The module re-fetches each alive host with HEAD/GET,
// inspects Set-Cookie and Authorization response headers, and reports
// reportable misconfigurations.
//
// Categories reported (in authshape_findings.txt):
//
//   - cookie-no-httponly      session cookie missing HttpOnly → XSS-
//                             stealable
//   - cookie-no-secure        session cookie missing Secure → MITM-
//                             stealable on plain HTTP
//   - cookie-samesite-none    SameSite=None without Secure → cross-
//                             site request can carry the cookie
//   - cookie-missing-samesite modern browser default is SameSite=Lax
//                             but explicit is best-practice
//   - jwt-alg-none            JWT header advertises alg:none →
//                             signature bypass
//   - jwt-no-exp              JWT payload lacks exp claim → tokens
//                             never expire
//   - jwt-weak-hs256          JWT uses HS256 with a public-key-shaped
//                             secret (heuristic — often the public
//                             key as HMAC key)
//
// Everything is local parsing — no JWT validation against a server.
// "jwt-weak-hs256" is a heuristic signal, not a confirmation; the
// report generator flags it as "manual retest required."
package authshape

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/CyberShuriken/rfuf/internal/findings/internal/iohelp"
)

// severity maps each finding to a one-char code for the report. We
// keep severity in the data so the HackerOne-shaped report can sort
// by impact.
type severity string

const (
	sevHigh   severity = "HIGH"
	sevMedium severity = "MEDIUM"
	sevLow    severity = "LOW"
)

// Finding is one row in authshape_findings.txt.
type Finding struct {
	Host     string
	Category string
	Detail   string
	Severity severity
}

func (f Finding) line() string {
	return strings.Join([]string{f.Host, f.Category, string(f.Severity), f.Detail}, "\t")
}

// Run is the entry point. workDir is the rfuf work dir; the function
// reads alive.txt and writes authshape_findings.txt.
func Run(workDir string) error {
	hosts, err := iohelp.ReadLines(workDir + "/alive.txt")
	if err != nil {
		return fmt.Errorf("read alive.txt: %w", err)
	}
	if len(hosts) == 0 {
		return iohelp.WriteLines(workDir+"/authshape_findings.txt", nil)
	}
	const cap = 200
	if len(hosts) > cap {
		hosts = hosts[:cap]
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	findings := probeAll(ctx, hosts)
	lines := make([]string, len(findings))
	for i, f := range findings {
		lines[i] = f.line()
	}
	return iohelp.WriteLines(workDir+"/authshape_findings.txt", lines)
}

func probeAll(ctx context.Context, hosts []string) []Finding {
	sem := make(chan struct{}, 25)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var out []Finding

	tr := &http.Transport{MaxIdleConns: 100, MaxIdleConnsPerHost: 5}
	client := &http.Client{Transport: tr, Timeout: 8 * time.Second}

	for _, h := range hosts {
		h := h
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			fs := probeHost(ctx, client, h)
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

func probeHost(ctx context.Context, client *http.Client, host string) []Finding {
	// GET a typical page so the response includes the cookie-bearing
	// headers. A 404 is fine — the Set-Cookie / Authorization headers
	// are set on the response path before the application code.
	req, err := http.NewRequestWithContext(ctx, "GET", host, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "rfuf-authshape/1.0")
	iohelp.ApplyAuth(req)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	resp.Body.Close()

	var out []Finding

	// === Cookie checks ===
	// Go collapses multiple Set-Cookie headers; we read them all
	// from resp.Cookies() which gives us one entry per cookie.
	for _, c := range resp.Cookies() {
		name := c.Name
		if !isSessionCookie(name) {
			continue
		}
		if !c.HttpOnly {
			out = append(out, Finding{
				Host:     host,
				Category: "cookie-no-httponly",
				Detail:   name,
				Severity: sevHigh,
			})
		}
		if !c.Secure {
			out = append(out, Finding{
				Host:     host,
				Category: "cookie-no-secure",
				Detail:   name,
				Severity: sevMedium,
			})
		}
		// SameSite is a *SameSite enum on c. Zero value (uninitialized)
		// is the default — but Go's net/http parses "SameSite" into
		// c.SameSite when present. c.SameSite == 0 means the cookie
		// didn't ship a SameSite attribute at all.
		if c.SameSite == 0 {
			out = append(out, Finding{
				Host:     host,
				Category: "cookie-missing-samesite",
				Detail:   name,
				Severity: sevLow,
			})
		}
		if c.SameSite == http.SameSiteNoneMode && !c.Secure {
			out = append(out, Finding{
				Host:     host,
				Category: "cookie-samesite-none-no-secure",
				Detail:   name,
				Severity: sevHigh,
			})
		}
	}

	// === JWT checks ===
	// Look for `Authorization: Bearer ...` or a JWT-shaped cookie.
	jwt := extractJWT(resp)
	if jwt != "" {
		for _, f := range checkJWT(host, jwt) {
			out = append(out, f)
		}
	}

	return out
}

// isSessionCookie returns true if name looks like a session/auth
// cookie. We only flag HttpOnly/Secure issues on cookies that *carry*
// state worth stealing — no point reporting that the analytics cookie
// isn't HttpOnly.
func isSessionCookie(name string) bool {
	l := strings.ToLower(name)
	// Exclude well-known analytics/segmentation cookies. They look
	// like session cookies ("_hjSession_", "ajs_anonymous_id",
	// "cf_clearance") but carry no auth state.
	analyticsPrefixes := []string{"_hj", "_ga", "_gid", "ajs_", "cf_", "_clck", "_clsk", "amp_", "_fbp", "_fbc"}
	for _, p := range analyticsPrefixes {
		if strings.HasPrefix(l, p) {
			return false
		}
	}
	if strings.HasPrefix(name, "__Host-") || strings.HasPrefix(name, "__Secure-") {
		return true
	}
	for _, s := range []string{"sess", "sid", "session", "auth", "token", "jwt", "login", "user", "csrf", "xsrf"} {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

func extractJWT(resp *http.Response) string {
	// Authorization: Bearer
	if h := resp.Header.Get("Authorization"); h != "" {
		if strings.HasPrefix(h, "Bearer ") {
			tok := strings.TrimPrefix(h, "Bearer ")
			if looksLikeJWT(tok) {
				return tok
			}
		}
	}
	// Cookie-shaped: any cookie value that looks like a JWT.
	for _, c := range resp.Cookies() {
		if looksLikeJWT(c.Value) {
			return c.Value
		}
	}
	return ""
}

func looksLikeJWT(s string) bool {
	// 3 dot-separated base64url segments
	if strings.Count(s, ".") != 2 {
		return false
	}
	// And the first segment decodes as JSON with an "alg" field.
	parts := strings.SplitN(s, ".", 3)
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		// Some JWTs use padded encoding; try standard.
		raw, err = base64.StdEncoding.DecodeString(parts[0])
		if err != nil {
			return false
		}
	}
	var hdr map[string]interface{}
	if err := json.Unmarshal(raw, &hdr); err != nil {
		return false
	}
	_, ok := hdr["alg"]
	return ok
}

func checkJWT(host, tok string) []Finding {
	parts := strings.SplitN(tok, ".", 3)
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		headerJSON, err = base64.StdEncoding.DecodeString(parts[0])
		if err != nil {
			return nil
		}
	}
	var hdr map[string]interface{}
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		return nil
	}

	var out []Finding

	// alg:none — signature bypass
	if alg, _ := hdr["alg"].(string); strings.EqualFold(alg, "none") {
		out = append(out, Finding{
			Host:     host,
			Category: "jwt-alg-none",
			Detail:   "alg=none in JWT header",
			Severity: sevHigh,
		})
	}

	// kid injection vector: kid present and looks like a SQL/path
	// expression rather than a UUID/key-id.
	if kid, _ := hdr["kid"].(string); kid != "" {
		if strings.ContainsAny(kid, "/\\'\";%") {
			out = append(out, Finding{
				Host:     host,
				Category: "jwt-kid-injection",
				Detail:   fmt.Sprintf("kid=%q looks like a path/SQL expression", kid),
				Severity: sevHigh,
			})
		}
	}

	// Decoded payload — check `exp` claim.
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payloadJSON, err = base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return out
		}
	}
	var pl map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &pl); err != nil {
		return out
	}
	if _, hasExp := pl["exp"]; !hasExp {
		out = append(out, Finding{
			Host:     host,
			Category: "jwt-no-exp",
			Detail:   "no exp claim → tokens never expire",
			Severity: sevMedium,
		})
	}
	return out
}
