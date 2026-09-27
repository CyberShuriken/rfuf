package iohelp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/CyberShuriken/rfuf/internal/scope"
)

type requestPolicy struct {
	scope   scope.Scope
	exclude *regexp.Regexp
}

type policyTransport struct {
	base   http.RoundTripper
	policy requestPolicy
}

func (t policyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.policy.validate(req.URL); err != nil {
		return nil, err
	}
	ApplyAuth(req)
	return t.base.RoundTrip(req)
}

func (p requestPolicy) validate(u *url.URL) error {
	if u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return errors.New("request blocked: invalid_url")
	}
	if !p.scope.IncludesHost(u.Hostname()) {
		return errors.New("request blocked: out_of_scope")
	}
	if p.exclude != nil && p.exclude.MatchString(u.String()) {
		return errors.New("request blocked: excluded")
	}
	return nil
}

func policyFromEnv() (requestPolicy, error) {
	input := strings.TrimSpace(os.Getenv("RFUF_SCOPE_INPUT"))
	if input == "" {
		return requestPolicy{}, errors.New("request blocked: scope_not_configured")
	}
	parsed, err := scope.Parse(input)
	if err != nil {
		return requestPolicy{}, errors.New("request blocked: invalid_scope")
	}
	var exclude *regexp.Regexp
	if expression := strings.TrimSpace(os.Getenv("RFUF_EXCLUDE_URL_REGEX")); expression != "" {
		exclude, err = regexp.Compile(expression)
		if err != nil {
			return requestPolicy{}, errors.New("request blocked: invalid_exclusion_policy")
		}
	}
	return requestPolicy{scope: parsed, exclude: exclude}, nil
}

// ConfigureFromWorkDir loads the persisted scope before dispatching an
// internal finder. RFUF_SCOPE_INPUT supplied by the pipeline takes
// precedence; the scope file supports explicit local finder dispatch.
func ConfigureFromWorkDir(workDir string) error {
	if strings.TrimSpace(os.Getenv("RFUF_SCOPE_INPUT")) != "" {
		_, err := policyFromEnv()
		return err
	}
	data, err := os.ReadFile(filepath.Join(workDir, "scope.json"))
	if err != nil {
		return errors.New("finder request policy unavailable: scope metadata missing")
	}
	var persisted struct {
		Input string `json:"input"`
	}
	if err := json.Unmarshal(data, &persisted); err != nil || persisted.Input == "" {
		return errors.New("finder request policy unavailable: invalid scope metadata")
	}
	if _, err := scope.Parse(persisted.Input); err != nil {
		return errors.New("finder request policy unavailable: invalid scope metadata")
	}
	if err := os.Setenv("RFUF_SCOPE_INPUT", persisted.Input); err != nil {
		return fmt.Errorf("configure finder scope: %w", err)
	}
	_, err = policyFromEnv()
	return err
}

// NewRequestWithContext constructs an authenticated HTTP request only when
// its destination passes the active exact/wildcard scope and exclusion.
func NewRequestWithContext(ctx context.Context, method, rawURL string, body io.Reader) (*http.Request, error) {
	policy, err := policyFromEnv()
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, errors.New("request blocked: invalid_url")
	}
	if err := policy.validate(u); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, errors.New("request construction failed")
	}
	ApplyAuth(req)
	return req, nil
}

func NewRequest(method, rawURL string, body io.Reader) (*http.Request, error) {
	return NewRequestWithContext(context.Background(), method, rawURL, body)
}

// HardenClient enforces scope, exclusion, and auth at the transport boundary
// for every request, including redirect hops and requests made by callers
// that have not yet migrated to NewRequestWithContext.
func HardenClient(client *http.Client) {
	if client == nil {
		return
	}
	if _, ok := client.Transport.(policyTransport); ok {
		return
	}
	policy, err := policyFromEnv()
	if err != nil {
		// Fail closed. RunFinder validates scope metadata before calling a
		// finder; direct module callers without policy must never send.
		policy = requestPolicy{}
	}
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	client.Transport = policyTransport{base: base, policy: policy}
}

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
		// Preserve the legacy header for existing programs and also send
		// HackerOne's standard attribution header when required.
		out = append(out,
			struct{ Key, Value string }{"X-Bug-Bounty", username},
			struct{ Key, Value string }{"X-HackerOne-Research", username},
		)
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
