package iohelp

import (
	"net/http"
	"os"
	"strings"
)

// BuildAuthHeaders returns the Go http.Header entries that should be
// appended to every outbound request sent by an rfuf findings module.
//
// Authorization precedence:
//
//  1. RFUF_AUTH_HEADER — set explicitly by the user via `-auth-bearer`.
//     The string may or may not include the "Bearer " prefix; both are
//     accepted. Used as the full Authorization header value.
//  2. RFUF_AUTH_COOKIE — set explicitly by the user via `-auth-cookie`.
//     Wrapped in `Cookie: <value>` for direct injection.
//  3. RFUF_BUG_BOUNTY_USERNAME and RFUF_TEST_ACCOUNT_EMAIL — optional
//     program-attribution headers used when a bounty program requires them.
//
// Either or both may be unset. The returned slice is suitable to be
// applied by `req.Header["..."] = [...]` or appended via
// `req.Header.Add(...)`. We return raw header keys so the caller can
// decide whether to Add (multi-value) or Set (replace).
//
// The two keys (Authorization, Cookie) are intentionally NOT both set
// for the same request — that would be redundant. Authorization wins
// when both env vars are present.
//
// Note: this is the Go-side helper. Bash stage commands in pipeline.go
// use a parallel build_auth_headers() snippet that translates the same
// env vars into tool-specific flags (-H for httpx/nuclei, --cookie for
// sqlmap, --headers for dalfox).
//
// Security note: the auth values are read from process env, never
// written to a findings file. Findings files contain only URLs (no
// cookies, no tokens). Verified secrets (trufflehog) are written only
// after the value is masked.
func BuildAuthHeaders() []struct{ Key, Value string } {
	var out []struct{ Key, Value string }
	bearer := strings.TrimSpace(os.Getenv("RFUF_AUTH_HEADER"))
	cookie := strings.TrimSpace(os.Getenv("RFUF_AUTH_COOKIE"))
	if bearer != "" {
		// Accept both "Bearer xxx" and "xxx" forms.
		if !strings.HasPrefix(strings.ToLower(bearer), "bearer ") {
			bearer = "Bearer " + bearer
		}
		out = append(out, struct{ Key, Value string }{"Authorization", bearer})
	}
	if cookie != "" {
		// Cookie value format: either "k1=v1; k2=v2" (multi-cookie
		// form, sent directly) or bare "k=v" (single cookie). We
		// pass through verbatim.
		out = append(out, struct{ Key, Value string }{"Cookie", cookie})
	}
	if username := strings.TrimSpace(os.Getenv("RFUF_BUG_BOUNTY_USERNAME")); username != "" {
		out = append(out, struct{ Key, Value string }{"X-Bug-Bounty", username})
	}
	if email := strings.TrimSpace(os.Getenv("RFUF_TEST_ACCOUNT_EMAIL")); email != "" {
		out = append(out, struct{ Key, Value string }{"X-Test-Account-Email", email})
	}
	return out
}

// ApplyAuth attaches the BuildAuthHeaders() entries to req. Idempotent:
// safe to call multiple times — the http.Request dedupes by header key.
func ApplyAuth(req *http.Request) {
	for _, h := range BuildAuthHeaders() {
		// Use Set so we don't leak the same header if a stage rebuilds
		// the request internally. Most modules build the request once.
		req.Header.Set(h.Key, h.Value)
	}
}
