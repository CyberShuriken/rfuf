// Package cors2 implements F15: credentialed CORS preflight check.
//
// The existing inline bash CORS check (cors_check stage) only
// inspects the ACAO header from a simple cross-origin GET. That
// misses three real bug classes:
//
//  1. Preflight responses — when the client sends a non-simple
//     request (Content-Type: application/json, custom headers), the
//     browser issues an OPTIONS preflight first. The preflight
//     response can allow cross-origin POSTs with credentials while
//     the simple GET would not.
//  2. ACAO-Credentials combos where ACAO is reflected but ACAC is
//     missing on a 200 simple request that the inline check might
//     misclassify.
//  3. Null origin — a server that responds with `Access-Control-
//     Allow-Origin: null` together with `Allow-Credentials: true` is
//     exploitable from sandboxed iframes (sandboxed iframes have a
//     null origin and can carry cookies the parent's iframes can't).
//
// What this module does:
//
//  - For each alive host, issue an OPTIONS request with a CORS
//    request signature: `Origin: https://attacker.example` plus
//    `Access-Control-Request-Method: POST` and a custom header
//    (`X-Requested-With`). The OPTIONS response is the preflight
//    response.
//  - Read ACAO, ACAC, ACA-Methods, ACA-Headers from the preflight.
//  - Issue a simple GET with Origin too (for null-origin cases) and
//    record the ACAO.
//
// Output: cors2_findings.txt with rows:
//
//	host<TAB>vector<TAB>acao<TAB>acac<TAB>severity
//
// `vector` is one of: preflight-credentialed, null-origin-reflected,
// null-origin-wildcard. `severity` reflects realistic exploitability.
package cors2

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/CyberShuriken/rfuf/internal/findings/internal/iohelp"
)

// attackerOrigin is the marker we send. We don't own attacker.example
// — the candidate payload is the *shape* of the test, not a real
// attacker domain. Same convention as the oauth module.
const attackerOrigin = "https://attacker.example"

// Run is the entry point. workDir is the rfuf work dir.
func Run(workDir string) error {
	hosts, err := iohelp.ReadLines(workDir + "/alive.txt")
	if err != nil {
		return fmt.Errorf("read alive.txt: %w", err)
	}
	if len(hosts) == 0 {
		return iohelp.WriteLines(workDir+"/cors2_findings.txt", nil)
	}
	const cap = 200
	if len(hosts) > cap {
		hosts = hosts[:cap]
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	rows := probeAll(ctx, hosts)
	return iohelp.WriteLines(workDir+"/cors2_findings.txt", rows)
}

func probeAll(ctx context.Context, hosts []string) []string {
	sem := make(chan struct{}, 25)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var out []string

	tr := &http.Transport{MaxIdleConns: 100, MaxIdleConnsPerHost: 5}
	client := &http.Client{
		Transport: tr,
		Timeout:   8 * time.Second,
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
			rs := probeHost(ctx, client, h)
			if len(rs) > 0 {
				mu.Lock()
				out = append(out, rs...)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return out
}

func probeHost(ctx context.Context, client *http.Client, host string) []string {
	var out []string

	// === Probe 1: credentialed preflight (OPTIONS) ===
	// The preflight response is what controls whether a non-simple
	// request (POST application/json from the attacker's origin)
	// goes through. The simple-GET check in the existing inline
	// bash stage does NOT test this.
	if r := preflightProbe(ctx, client, host, attackerOrigin); r != "" {
		out = append(out, r)
	}

	// === Probe 2: null origin ===
	// Browsers send `Origin: null` for sandboxed iframes, file://
	// pages, and some redirects. A server that echoes null in ACAO
	// AND sets Allow-Credentials is exploitable from any sandboxed
	// iframe on the internet.
	if r := originProbe(ctx, client, host, "null"); r != "" {
		out = append(out, r)
	}

	return out
}

func preflightProbe(ctx context.Context, client *http.Client, host, origin string) string {
	req, err := http.NewRequestWithContext(ctx, "OPTIONS", host, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "X-Requested-With, Content-Type")
	req.Header.Set("User-Agent", "rfuf-cors2/1.0")
	iohelp.ApplyAuth(req)

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	resp.Body.Close()

	acao := strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Origin"))
	acac := strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Credentials"))
	acam := strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Methods"))

	// A preflight that allows credentials + our origin is exploitable.
	if (acao == origin || acao == "*") && strings.EqualFold(acac, "true") {
		// * with credentials is invalid per spec but some servers
		// still emit it. Flag it anyway.
		if acao == "*" {
			return fmt.Sprintf("%s\tpreflight-wildcard-credentials\t%s\t%s\tmethods=%s\tHIGH",
				host, acao, acac, acam)
		}
		return fmt.Sprintf("%s\tpreflight-credentialed\t%s\t%s\tmethods=%s\tHIGH",
			host, acao, acac, acam)
	}

	// Allow-Methods includes POST but ACAO is missing/wildcard without
	// credentials — possible misconfiguration worth flagging at LOW.
	if acam != "" && (acao == "*" || acao == origin) && !strings.EqualFold(acac, "true") {
		return fmt.Sprintf("%s\tpreflight-allows-post\t%s\t%s\tmethods=%s\tLOW",
			host, acao, acac, acam)
	}
	return ""
}

func originProbe(ctx context.Context, client *http.Client, host, origin string) string {
	req, err := http.NewRequestWithContext(ctx, "GET", host, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Origin", origin)
	req.Header.Set("User-Agent", "rfuf-cors2/1.0")
	iohelp.ApplyAuth(req)

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	resp.Body.Close()

	acao := strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Origin"))
	acac := strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Credentials"))

	if acao == "" {
		return ""
	}

	// null origin reflected + credentials = sandboxed-iframe exploit.
	if origin == "null" && strings.EqualFold(acao, "null") && strings.EqualFold(acac, "true") {
		return fmt.Sprintf("%s\tnull-origin-reflected\t%s\t%s\tHIGH",
			host, acao, acac)
	}
	return ""
}