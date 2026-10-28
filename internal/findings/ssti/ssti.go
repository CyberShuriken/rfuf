// Package ssti probes query parameters for server-side template injection by
// substituting arithmetic polyglots and checking whether the server EVALUATED
// them (the product appears) rather than merely reflecting the literal.
//
//   - CONFIRMED: a polyglot like {{7*7}} comes back as 49 (evaluation) — real SSTI.
//   - CANDIDATE: the polyglot is reflected verbatim (reflection, not eval) — an
//     XSS-ish lead, not confirmed SSTI; left for manual engine fingerprinting.
//
// Hosts are gated through iohelp.InScope; requests use the scope-hardened client.
package ssti

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

const urlCap = 1500

// polyglots pair an injection string with the product string that only appears
// if the template engine evaluated it. 7*7=49, 7*'7' differs per engine.
var polyglots = []struct{ payload, product, engine string }{
	{"{{7*7}}", "49", "jinja2/twig/nunjucks"},
	{"${7*7}", "49", "freemarker/JSP-EL/ES-template"},
	{"<%= 7*7 %>", "49", "erb/ejs"},
	{"#{7*7}", "49", "ruby/thymeleaf"},
	{"{{7*'7'}}", "7777777", "jinja2"},
}

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
		if err != nil || u.Host == "" || !iohelp.InScope(u.Hostname()) || len(u.Query()) == 0 {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(u *url.URL) {
			defer wg.Done()
			defer func() { <-sem }()
			for param := range u.Query() {
				state, detail := probeParam(ctx, client, u, param)
				if state == "" {
					continue
				}
				mu.Lock()
				if state == "confirmed" {
					confirmed = append(confirmed, "HIGH\t"+u.String()+"\tssti\tparam="+param+"\t"+detail)
				} else {
					candidates = append(candidates, u.String()+"\tssti\tparam="+param+"\t"+detail+"\tvalidation=candidate")
				}
				mu.Unlock()
			}
		}(u)
	}
	wg.Wait()
	return writeOut(workDir, confirmed, candidates)
}

func probeParam(ctx context.Context, client *http.Client, u *url.URL, param string) (state, detail string) {
	for _, p := range polyglots {
		body := fetch(ctx, client, withParam(u, param, p.payload))
		if body == "" {
			continue
		}
		if strings.Contains(body, p.product) {
			return "confirmed", "evaluated " + p.payload + " -> " + p.product + " (" + p.engine + ")"
		}
		if strings.Contains(body, p.payload) {
			// Reflected literally — not evaluated. Lead only.
			return "candidate", "payload reflected literally (reflection, not eval)"
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

func fetch(ctx context.Context, client *http.Client, rawURL string) string {
	req, err := iohelp.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "rfuf-ssti/1.0")
	iohelp.ApplyAuth(req)
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	return string(body)
}

func hardenedClient() *http.Client {
	c := &http.Client{Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	iohelp.HardenClient(c)
	return c
}

func writeOut(workDir string, confirmed, candidates []string) error {
	if err := iohelp.WriteLines(workDir+"/ssti_findings.txt", confirmed); err != nil {
		return err
	}
	return iohelp.WriteLines(workDir+"/ssti_candidates.txt", candidates)
}
