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
	iohelp.HardenClient(client)

	seen := map[string]bool{}
	for _, urlStr := range urls {
		if !isObjectStoreCandidate(urlStr) {
			continue
		}
		root := strings.TrimRight(urlStr, "/")
		if seen[root] {
			continue
		}
		seen[root] = true

		status, body, hdr := fetchRoot(client, root)

		// A custom/CloudFront domain is still worth flagging when the origin is
		// AmazonS3 (revealed by response headers), not just when the hostname
		// literally contains "s3".
		if region := hdr.Get("x-amz-bucket-region"); region != "" {
			findings = append(findings, fmt.Sprintf("[S3-ORIGIN] %s - AmazonS3-backed (region=%s)", root, region))
		} else if strings.Contains(strings.ToLower(hdr.Get("Server")), "amazons3") {
			findings = append(findings, fmt.Sprintf("[S3-ORIGIN] %s - AmazonS3-backed (Server header)", root))
		}

		// A real public listing returns an S3 ListBucketResult document, not
		// merely HTTP 200 (a CloudFront 200 on index.html is not a listing).
		switch {
		case status == 200 && strings.Contains(body, "<ListBucketResult"):
			findings = append(findings, fmt.Sprintf("[LISTED] %s - public bucket listing enabled (%d objects visible)", root, strings.Count(body, "<Key>")))
		case status == 200 && strings.Contains(body, "<?xml") && strings.Contains(body, "<Contents>"):
			findings = append(findings, fmt.Sprintf("[LISTED] %s - public object listing", root))
		}

		// Probe only with GET requests. Write permissions require explicit,
		// operator-directed validation and are never tested automatically.
		for _, file := range sensitiveFiles {
			target := root + "/" + file
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

// isObjectStoreCandidate gates which URLs are worth a root probe. It covers the
// classic S3 hostnames plus CloudFront and other object-store fronts, so an
// S3-backed CDN origin (confirmed later via response headers) is not skipped on
// the hostname alone.
func isObjectStoreCandidate(url string) bool {
	url = strings.ToLower(url)
	patterns := []string{
		"s3.amazonaws.com", "s3-", "s3.dualstack", ".s3.", "cdn-s3", "bucket",
		"minio", "digitaloceanspaces", "cloudfront.net",
		"storage.googleapis.com", "blob.core.windows.net", ".r2.dev",
	}
	for _, p := range patterns {
		if strings.Contains(url, p) {
			return true
		}
	}
	return false
}

// fetchRoot GETs a bucket/CDN root and returns the status, a bounded body
// snippet (enough to recognise an S3 ListBucketResult), and the headers.
func fetchRoot(client *http.Client, url string) (int, string, http.Header) {
	req, err := iohelp.NewRequest("GET", url, nil)
	if err != nil {
		return 0, "", http.Header{}
	}
	iohelp.ApplyAuth(req)
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", http.Header{}
	}
	defer resp.Body.Close()
	buf := make([]byte, 16*1024)
	n, _ := resp.Body.Read(buf)
	return resp.StatusCode, string(buf[:n]), resp.Header
}

func getStatusCode(client *http.Client, url string) int {
	req, err := iohelp.NewRequest("GET", url, nil)
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
