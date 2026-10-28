// Package cachepoison probes CloudFront/CDN-fronted URLs for web cache
// poisoning (unkeyed-header reflection that gets cached) and cache deception
// (dynamic content served under a static-looking path that the CDN caches).
//
//   - CONFIRMED: an unkeyed header (X-Forwarded-Host etc.) is reflected AND a
//     second request WITHOUT the header still returns the injected value, or the
//     response shows a cache HIT carrying it — the poison persisted in cache.
//   - CANDIDATE: the header is reflected but not demonstrably cached, or a
//     static-extension path returns dynamic content with cache headers — leads
//     needing manual cache-key analysis.
//
// Hosts gated through iohelp.InScope; scope-hardened client.
package cachepoison

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

const (
	urlCap   = 800
	canary   = "rfufcache7f3.example.com"
	cacheHit = "hit"
)

// unkeyedHeaders are commonly-unkeyed headers that apps reflect into responses.
var unkeyedHeaders = []string{"X-Forwarded-Host", "X-Forwarded-Scheme", "X-Host", "X-Forwarded-Server"}

func Run(workDir string) error {
	urls, err := iohelp.ReadLines(workDir + "/all_urls_200.txt")
	if err != nil || len(urls) == 0 {
		// Fall back to alive hosts if the 200 lane is empty.
		urls, _ = iohelp.ReadLines(workDir + "/alive.txt")
	}
	if len(urls) == 0 {
		return writeOut(workDir, nil, nil)
	}
	if len(urls) > urlCap {
		urls = urls[:urlCap]
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	client := hardenedClient()

	var mu sync.Mutex
	var confirmed, candidates []string
	sem := make(chan struct{}, 15)
	var wg sync.WaitGroup
	seen := map[string]bool{}
	for _, raw := range urls {
		field := strings.Fields(raw)
		if len(field) == 0 {
			continue
		}
		u, err := url.Parse(field[0])
		if err != nil || u.Host == "" || !iohelp.InScope(u.Hostname()) {
			continue
		}
		key := u.Scheme + "://" + u.Host + u.Path
		if seen[key] {
			continue
		}
		seen[key] = true
		wg.Add(1)
		sem <- struct{}{}
		go func(u *url.URL) {
			defer wg.Done()
			defer func() { <-sem }()
			if state, detail := probePoison(ctx, client, u); state != "" {
				mu.Lock()
				if state == "confirmed" {
					confirmed = append(confirmed, "HIGH\t"+u.String()+"\tcache_poisoning\t"+detail)
				} else {
					candidates = append(candidates, u.String()+"\tcache_poisoning\t"+detail+"\tvalidation=candidate")
				}
				mu.Unlock()
			}
			if detail := probeDeception(ctx, client, u); detail != "" {
				mu.Lock()
				candidates = append(candidates, u.String()+"\tcache_deception\t"+detail+"\tvalidation=candidate")
				mu.Unlock()
			}
		}(u)
	}
	wg.Wait()
	return writeOut(workDir, confirmed, candidates)
}

// probePoison injects an unkeyed header and checks reflection + cache persistence.
func probePoison(ctx context.Context, client *http.Client, u *url.URL) (state, detail string) {
	for _, h := range unkeyedHeaders {
		_, body, _ := do(ctx, client, u.String(), map[string]string{h: canary})
		if !strings.Contains(body, canary) {
			continue
		}
		// Reflected. Now fetch WITHOUT the header to see if the poison is cached.
		_, body2, hdr2 := do(ctx, client, u.String(), nil)
		if strings.Contains(body2, canary) {
			return "confirmed", h + " reflected and persisted unkeyed (poison cached)"
		}
		if strings.EqualFold(cacheStatus(hdr2), cacheHit) {
			return "candidate", h + " reflected; response is a cache HIT — verify cache key"
		}
		return "candidate", h + " reflected in response (unkeyed-header reflection)"
	}
	return "", ""
}

// probeDeception appends a static extension and checks for cached dynamic content.
func probeDeception(ctx context.Context, client *http.Client, u *url.URL) string {
	if strings.Contains(u.Path, ".") && !strings.HasSuffix(u.Path, "/") {
		return "" // already a file-ish path
	}
	decoy := *u
	decoy.Path = strings.TrimRight(u.Path, "/") + "/rfufcache.css"
	status, _, hdr := do(ctx, client, decoy.String(), nil)
	if status == 200 && strings.Contains(strings.ToLower(hdr.Get("Content-Type")), "html") {
		return "static-ext path " + decoy.Path + " returned 200 HTML (cache-deception surface, cache=" + cacheStatus(hdr) + ")"
	}
	return ""
}

func do(ctx context.Context, client *http.Client, rawURL string, headers map[string]string) (int, string, http.Header) {
	req, err := iohelp.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return 0, "", http.Header{}
	}
	req.Header.Set("User-Agent", "rfuf-cachepoison/1.0")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	iohelp.ApplyAuth(req)
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", http.Header{}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	return resp.StatusCode, string(body), resp.Header
}

// cacheStatus normalizes the common CDN cache-status headers to hit/miss/"".
func cacheStatus(h http.Header) string {
	for _, k := range []string{"X-Cache", "CF-Cache-Status", "X-Cache-Status", "Age"} {
		v := strings.ToLower(h.Get(k))
		if strings.Contains(v, "hit") {
			return "hit"
		}
		if k == "Age" && v != "" && v != "0" {
			return "hit"
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

func writeOut(workDir string, confirmed, candidates []string) error {
	if err := iohelp.WriteLines(workDir+"/cache_poisoning_findings.txt", confirmed); err != nil {
		return err
	}
	return iohelp.WriteLines(workDir+"/cache_poisoning_candidates.txt", candidates)
}
