package s3auditor

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
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
		if writeErr := iohelp.WriteLines(workDir+"/s3_audit_findings.txt", []string{}); writeErr != nil {
			return writeErr
		}
		return writeStatus(workDir, "completed_no_input")
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

		// Probe only with GET requests. Write permissions require explicit,
		// operator-directed validation and are never tested automatically.
		for _, file := range sensitiveFiles {
			target := fmt.Sprintf("%s/%s", strings.TrimRight(urlStr, "/"), file)
			if getStatusCode(client, target) == 200 {
				findings = append(findings, fmt.Sprintf("[EXPOSED] %s - Found sensitive file", target))
			}
		}
	}

	if err := iohelp.WriteLines(workDir+"/s3_audit_findings.txt", findings); err != nil {
		return err
	}
	return writeStatus(workDir, "completed")
}

func writeStatus(workDir, status string) error {
	data, err := json.Marshal(map[string]any{"status": status, "write_permission_test": "not_performed", "reason": "non_destructive_mode"})
	if err != nil {
		return err
	}
	return os.WriteFile(workDir+"/s3_audit_status.json", append(data, '\n'), 0644)
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

func getStatusCode(client *http.Client, url string) int {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0
	}
	iohelp.ApplyAuth(req)
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	return resp.StatusCode
}
