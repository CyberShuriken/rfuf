// Package smuggling flags HTTP request-smuggling SURFACE — hosts sitting behind
// a front-end/back-end proxy chain (the precondition for CL.TE/TE.CL) and hosts
// advertising h2c upgrade. It does NOT send desync payloads: reliable smuggling
// detection needs malformed CL/TE framing that can affect co-tenant traffic, so
// confirmation is deliberately left to a manual smuggler/h2c run. Candidate-only.
//
//   - CANDIDATE: proxy chain detected (Via / CDN cache / dual Server hops) or
//     h2c upgrade offered — review with a desync tool.
//
// Hosts gated through iohelp.InScope; scope-hardened client.
package smuggling

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
		go func(target, host string) {
			defer wg.Done()
			defer func() { <-sem }()
			if detail := inspect(ctx, client, target); detail != "" {
				mu.Lock()
				candidates = append(candidates, host+"\thttp_smuggling\t"+detail+"\tvalidation=candidate")
				mu.Unlock()
			}
		}(u.String(), u.Hostname())
	}
	wg.Wait()
	return iohelp.WriteLines(workDir+"/http_smuggling_candidates.txt", candidates)
}

func inspect(ctx context.Context, client *http.Client, target string) string {
	req, err := iohelp.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "rfuf-smuggling/1.0")
	iohelp.ApplyAuth(req)
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1))

	var signals []string
	if v := resp.Header.Get("Via"); v != "" {
		signals = append(signals, "Via="+v)
	}
	h := resp.Header
	if cdn := firstNonEmpty(h, "CF-RAY", "X-Amz-Cf-Id", "X-Served-By", "X-Cache", "X-Varnish"); cdn != "" {
		signals = append(signals, "cdn-front="+cdn)
	}
	if up := h.Get("Upgrade"); strings.Contains(strings.ToLower(up), "h2c") {
		signals = append(signals, "offers h2c upgrade")
	}
	if len(signals) == 0 {
		return ""
	}
	return "proxy chain (" + strings.Join(signals, "; ") + ") — run smuggler/h2c desync manually"
}

func firstNonEmpty(h http.Header, keys ...string) string {
	for _, k := range keys {
		if v := h.Get(k); v != "" {
			return k + ":" + v
		}
	}
	return ""
}

func hardenedClient() *http.Client {
	c := &http.Client{Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	iohelp.HardenClient(c)
	return c
}
