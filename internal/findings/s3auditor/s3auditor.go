package s3auditor

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/CyberShuriken/rfuf/internal/findings/internal/iohelp"
)

var sensitiveFiles = []string{
	"backup.zip", "config.json", "credentials.txt", ".env", "users.sql", "logs/error.log",
	"web.config", "settings.json", ".aws/credentials", ".ssh/id_rsa", "wp-config.php",
}

// Run audits discovered S3 buckets for misconfigurations.
func Run(workDir string) error {
	urls, err := iohelp.ReadLines(workDir + "/all_urls.txt")
	if err != nil || len(urls) == 0 {
		return iohelp.WriteLines(workDir+"/s3_audit_findings.txt", []string{})
	}

	var findings []string
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	for _, urlStr := range urls {
		if !isS3Bucket(urlStr) {
			continue
		}

		// 1. Test for ListBucket (Root)
		if getStatusCode(client, urlStr) == 200 {
			findings = append(findings, fmt.Sprintf("[LISTED] %s - Bucket listing is enabled", urlStr))
		}

		// 2. Test for PUT permissiveness (Write access)
		if checkPutPermission(client, urlStr) {
			findings = append(findings, fmt.Sprintf("[WRITE] %s - Bucket write access enabled (PUT successful)", urlStr))
		}

		// 3. Test for sensitive files
		for _, file := range sensitiveFiles {
			target := fmt.Sprintf("%s/%s", strings.TrimRight(urlStr, "/"), file)
			if getStatusCode(client, target) == 200 {
				findings = append(findings, fmt.Sprintf("[EXPOSED] %s - Found sensitive file", target))
			}
		}
	}

	return iohelp.WriteLines(workDir+"/s3_audit_findings.txt", findings)
}

func isS3Bucket(url string) bool {
	url = strings.ToLower(url)
	patterns := []string{
		"s3.amazonaws.com", "cdn-s3", "bucket", "s3-", "minio", "digitaloceanspaces",
	}
	for _, p := range patterns {
		if strings.Contains(url, p) {
			return true
		}
	}
	return false
}

func checkPutPermission(client *http.Client, urlStr string) bool {
	canaryFile := "rfuf_canary_test.txt"
	target := fmt.Sprintf("%s/%s", strings.TrimRight(urlStr, "/"), canaryFile)

	req, err := http.NewRequest("PUT", target, strings.NewReader("rfuf-test"))
	if err != nil {
		return false
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// 200 OK or 201 Created indicates success
	return resp.StatusCode == 200 || resp.StatusCode == 201
}

func getStatusCode(client *http.Client, url string) int {
	resp, err := client.Get(url)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	return resp.StatusCode
}
