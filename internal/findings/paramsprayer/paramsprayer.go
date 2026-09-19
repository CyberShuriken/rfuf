package paramsprayer

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/CyberShuriken/rfuf/internal/findings/internal/iohelp"
)

var sprayParams = map[string][]string{
	"admin":      {"true", "1", "yes"},
	"debug":      {"true", "1", "yes", "on"},
	"test":       {"true", "1", "yes", "on"},
	"dev":        {"true", "1", "yes", "on"},
	"privileged": {"true", "1", "yes"},
	"config":     {"true", "1", "yes"},
	"setup":      {"true", "1", "yes"},
	"internal":   {"true", "1", "yes"},
	"root":       {"true", "1", "yes"},
	"superuser":  {"true", "1", "yes"},
	"api_key":    {"test", "admin", "debug"},
}

// Run sprays hidden parameters on URLs that returned 200 OK.
func Run(workDir string) error {
	urls, err := iohelp.ReadLines(workDir + "/all_urls_200.txt")
	if err != nil || len(urls) == 0 {
		return iohelp.WriteLines(workDir+"/paramsprayer_candidates.txt", []string{})
	}

	var findings []string
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, urlStr := range urls {
		// Baseline
		resp, err := client.Get(urlStr)
		if err != nil {
			continue
		}
		baselineStatus := resp.StatusCode
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		baselineLen := len(body)

		for p, values := range sprayParams {
			for _, v := range values {
				testURL := urlStr
				if strings.Contains(testURL, "?") {
					testURL += "&" + p + "=" + v
				} else {
					testURL += "?" + p + "=" + v
				}

				res, err := client.Get(testURL)
				if err != nil {
					continue
				}
				resBody, err := io.ReadAll(res.Body)
				res.Body.Close()
				if err != nil {
					continue
				}
				resLen := len(resBody)

				if res.StatusCode != baselineStatus {
					findings = append(findings, fmt.Sprintf("[STATUS_CHANGE] %s -> %d (baseline %d)", testURL, res.StatusCode, baselineStatus))
				} else if resLen > 0 && baselineLen > 0 && (float64(resLen)/float64(baselineLen) > 1.2 || float64(resLen)/float64(baselineLen) < 0.8) {
					findings = append(findings, fmt.Sprintf("[LEN_CHANGE] %s -> %d bytes (baseline %d)", testURL, resLen, baselineLen))
				}
			}
		}
	}

	return iohelp.WriteLines(workDir+"/paramsprayer_candidates.txt", findings)
}
