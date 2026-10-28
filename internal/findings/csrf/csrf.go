// Package csrf flags cross-site request-forgery surface: session cookies set
// without an effective SameSite restriction, and state-changing (POST) endpoints
// that warrant a CSRF-token check. CSRF needs a hand-built cross-site PoC to
// confirm, so this emits candidates only — no confirmed tier.
//
//   - CANDIDATE (cookie): a session-ish cookie set with SameSite=None or no
//     SameSite attribute → cross-site requests will carry it.
//   - CANDIDATE (endpoint): a discovered POST endpoint (from JS mining) to
//     review for a CSRF token / SameSite pairing (pairs with oauth_audit).
//
// Hosts gated through iohelp.InScope; scope-hardened client.
package csrf

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/CyberShuriken/rfuf/internal/findings/internal/iohelp"
)

const urlCap = 400

// sessionCookieHints identify a cookie whose cross-site leakage matters.
var sessionCookieHints = []string{"session", "sess", "auth", "token", "jwt", "sid", "csrf", "login", "remember"}

func Run(workDir string) error {
	hosts, err := iohelp.ReadLines(workDir + "/alive.txt")
	if err != nil {
		hosts = nil
	}
	if len(hosts) > urlCap {
		hosts = hosts[:urlCap]
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	client := hardenedClient()

	var mu sync.Mutex
	var candidates []string
	sem := make(chan struct{}, 15)
	var wg sync.WaitGroup
	seen := map[string]bool{}
	for _, raw := range hosts {
		field := strings.Fields(raw)
		if len(field) == 0 {
			continue
		}
		u, err := url.Parse(field[0])
		if err != nil || u.Host == "" || !iohelp.InScope(u.Hostname()) || seen[u.Host] {
			continue
		}
		seen[u.Host] = true
		wg.Add(1)
		sem <- struct{}{}
		go func(target string, host string) {
			defer wg.Done()
			defer func() { <-sem }()
			for _, c := range weakCookies(ctx, client, target) {
				mu.Lock()
				candidates = append(candidates, host+"\tcsrf\tweak-samesite-cookie="+c+"\tvalidation=candidate")
				mu.Unlock()
			}
		}(u.String(), u.Hostname())
	}
	wg.Wait()

	// State-changing endpoints mined from JS — review targets for CSRF tokens.
	for _, line := range readLines(workDir, "js_post_targets.txt") {
		u, err := url.Parse(strings.Fields(line)[0])
		if err == nil && u.Host != "" && iohelp.InScope(u.Hostname()) {
			candidates = append(candidates, u.String()+"\tcsrf\tstate-changing-endpoint (review CSRF token)\tvalidation=candidate")
		}
	}

	return iohelp.WriteLines(workDir+"/csrf_candidates.txt", candidates)
}

// weakCookies returns names of session-ish cookies set without an effective
// SameSite restriction (None, or absent — which several stacks treat as Lax but
// older browsers as None; worth flagging).
func weakCookies(ctx context.Context, client *http.Client, target string) []string {
	req, err := iohelp.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "rfuf-csrf/1.0")
	iohelp.ApplyAuth(req)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1))
	var out []string
	for _, sc := range resp.Header.Values("Set-Cookie") {
		lower := strings.ToLower(sc)
		name := strings.TrimSpace(strings.SplitN(sc, "=", 2)[0])
		if !isSessionCookie(strings.ToLower(name)) {
			continue
		}
		if strings.Contains(lower, "samesite=none") || !strings.Contains(lower, "samesite=") {
			out = append(out, name)
		}
	}
	return out
}

func isSessionCookie(name string) bool {
	for _, h := range sessionCookieHints {
		if strings.Contains(name, h) {
			return true
		}
	}
	return false
}

func readLines(workDir, name string) []string {
	l, _ := iohelp.ReadLines(workDir + "/" + name)
	return l
}

func hardenedClient() *http.Client {
	c := &http.Client{Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	iohelp.HardenClient(c)
	return c
}
