// Package hostheader implements F14: Host header injection probing.
//
// Host header injection bugs surface in several flavors:
//
//   1. Password-reset poisoning — the server includes the Host header
//      in the password-reset email link, and an attacker who can
//      intercept the request (e.g. via X-Forwarded-Host from an
//      untrusted proxy) can put their own domain in the link.
//   2. Cache poisoning — CDN serves the response with the wrong Host
//      to subsequent users.
//   3. SSRF — the server uses Host to build a callback URL.
//   4. Open redirect — the server reflects Host in the redirect URL.
//
// Detection: send a request with a unique marker in the Host header
// and a separate request with X-Forwarded-Host / X-Original-URL
// containing the marker. Inspect the response body and headers for
// the marker. We do NOT issue the actual exploit (no password-reset
// requests, no email interception) — the test is purely passive.
//
// Output: hostheader_findings.txt with rows:
//
//	host<TAB>vector<TAB>marker<TAB>location<TAB>severity
//
// `vector` is the injection path (host-override, x-forwarded-host,
// x-original-url, x-host). `location` is where the marker appeared
// (body, location-header, link-header). `severity` reflects the
// realistic impact — Host-direct override on a server that doesn't
// validate is usually HIGH (cache poison + reset-poison); the proxy
// header variants are HIGH if reflected, MEDIUM otherwise.
package hostheader

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/CyberShuriken/rfuf/internal/findings/internal/iohelp"
)

// Run is the entry point. workDir is the rfuf work dir.
func Run(workDir string) error {
	hosts, err := iohelp.ReadLines(workDir + "/alive.txt")
	if err != nil {
		return fmt.Errorf("read alive.txt: %w", err)
	}
	if len(hosts) == 0 {
		return iohelp.WriteLines(workDir+"/hostheader_findings.txt", nil)
	}
	const cap = 200
	if len(hosts) > cap {
		hosts = hosts[:cap]
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	rows := probeAll(ctx, hosts)
	return iohelp.WriteLines(workDir+"/hostheader_findings.txt", rows)
}

// vectors are the Host-header mutation probes. Each one is an
// HTTP-header (or pseudo) that historically leaks into the response.
var vectors = []struct {
	name   string
	header string // "" means override the Host: header itself
	value  func(marker string) string
	sev    string
}{
	{
		name:   "host-override",
		header: "",
		value:  func(m string) string { return m + ".attacker.example" },
		sev:    "HIGH",
	},
	{
		name:   "x-forwarded-host",
		header: "X-Forwarded-Host",
		value:  func(m string) string { return m + ".attacker.example" },
		sev:    "HIGH",
	},
	{
		name:   "x-original-url",
		header: "X-Original-URL",
		value:  func(m string) string { return "/" + m },
		sev:    "MEDIUM",
	},
	{
		name:   "x-rewrite-url",
		header: "X-Rewrite-URL",
		value:  func(m string) string { return "/" + m },
		sev:    "MEDIUM",
	},
	{
		name:   "x-host",
		header: "X-Host",
		value:  func(m string) string { return m + ".attacker.example" },
		sev:    "MEDIUM",
	},
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
	marker := "rfufhh" + rand6()
	for _, v := range vectors {
		// Build the request. We use GET / so every server has a known
		// response shape to compare against.
		req, err := http.NewRequestWithContext(ctx, "GET", host, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "rfuf-hostheader/1.0")
		iohelp.ApplyAuth(req)

		val := v.value(marker)
		if v.header == "" {
			// Host override: rebuild the request on a different Host
			// while keeping the URL/path the same.
			req.Host = val
		} else {
			req.Header.Set(v.header, val)
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()

		bodyStr := string(body)
		// Look for marker in body, in Location header, and in Link
		// header. A hit in any of these is the bug.
		if strings.Contains(bodyStr, marker) {
			out = append(out, fmt.Sprintf("%s\t%s\tbody\t%s",
				host, v.name, v.sev))
		}
		if loc := resp.Header.Get("Location"); strings.Contains(loc, marker) {
			out = append(out, fmt.Sprintf("%s\t%s\tlocation-header\t%s",
				host, v.name, v.sev))
		}
		if l := resp.Header.Get("Link"); strings.Contains(l, marker) {
			out = append(out, fmt.Sprintf("%s\t%s\tlink-header\t%s",
				host, v.name, v.sev))
		}
	}
	return out
}

// rand6 returns a 6-char hex suffix. We don't need crypto-grade
// randomness — uniqueness within one host's probe batch is enough.
func rand6() string {
	const hex = "0123456789abcdef"
	now := time.Now().UnixNano()
	out := make([]byte, 6)
	for i := range out {
		out[i] = hex[(now>>(i*4))&0xf]
	}
	return string(out)
}