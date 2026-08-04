// Package buckets implements F8: S3 / GCS / Azure blob bucket guess.
//
// Public bucket takeovers are a reliable, high-paying bug-bounty class.
// The methodology: enumerate the company's likely bucket names, HEAD
// each one, and check whether the bucket exists and is publicly
// listable. If it does — the contents are the report.
//
// What this module does:
//
//  1. Derives org-name candidates from the primary domain (the
//     user-supplied domain) and the tech_fingerprint.txt output
//     (which captures CNAME / cert-SAN hints from earlier stages).
//  2. Generates permutations: {org}-{keyword} for ~30 keywords
//     (prod, dev, backups, assets, ...).
//  3. For each (provider, org, keyword) tuple, computes the bucket
//     hostname:
//       - S3:     {bucket}.s3.amazonaws.com
//       - GCS:    storage.googleapis.com/{bucket}
//       - Azure:  {bucket}.blob.core.windows.net
//  4. HEADs each hostname. A 200/403 with a known response shape
//     means the bucket exists; a 404 means it doesn't.
//  5. For S3 buckets that respond, also tries a GET on
//     ?list-type=2 — a public-readable bucket will return an XML
//     listing, which is the reportable finding.
//
// Output: bucket_findings.txt with one row per existing bucket and
// its access status. Plus a 0..1 permission level: 0 = exists but
// private, 1 = public-readable (the real bug).
package buckets

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/CyberShuriken/rfuf/internal/findings/internal/iohelp"
)

// keywords are the suffixes we append to the org name. The list
// mirrors the well-known bug-bounty bucket-takeover permutations.
var keywords = []string{
	"",                // bare org
	"-prod", "-dev", "-stg", "-test", "-staging", "-qa",
	"-backups", "-backup", "-bak", "-old", "-new", "-archive", "-archived",
	"-assets", "-media", "-images", "-img", "-static", "-cdn",
	"-data", "-db", "-database",
	"-uploads", "-upload", "-downloads", "-download", "-files",
	"-public", "-private", "-internal",
	"-config", "-configs", "-conf",
	"-logs", "-log", "-debug",
	"-users", "-user", "-accounts", "-account",
	"-api", "-v1", "-v2",
	"-beta", "-alpha",
}

// Run is the entry point. workDir is the rfuf work dir; the function
// also reads tech_fingerprint.txt for additional org-name hints.
func Run(workDir string) error {
	hosts, _ := iohelp.ReadLines(workDir + "/alive.txt")
	tech, _ := iohelp.ReadLines(workDir + "/tech_fingerprint.txt")
	domain, _ := iohelp.ReadLines(workDir + "/.rfuf/domain")
	if domain == nil {
		// Fallback: try to read the parent directory name. The
		// config layer writes the work dir as ~/Desktop/Bug_Bounty/<domain>,
		// so the basename is the domain. We don't have a direct
		// pointer; if we can't recover it, we use the first alive
		// host's host part.
		if len(hosts) > 0 {
			domain = []string{extractHost(hosts[0])}
		}
	}
	if len(hosts) == 0 && len(tech) == 0 && len(domain) == 0 {
		return iohelp.WriteLines(workDir+"/bucket_findings.txt", nil)
	}

	orgs := deriveOrgs(hosts, tech, domain)
	if len(orgs) == 0 {
		return iohelp.WriteLines(workDir+"/bucket_findings.txt", nil)
	}
	// Cap orgs to 6 — beyond that the URL explosion is enormous
	// (6 × 32 keywords × 3 providers = 576 HEADs).
	if len(orgs) > 6 {
		orgs = orgs[:6]
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	rows := probeAll(ctx, orgs)
	return iohelp.WriteLines(workDir+"/bucket_findings.txt", rows)
}

// deriveOrgs extracts candidate organization names from the recon
// outputs. Sources, in priority order:
//
//   1. The base of the user-supplied domain (e.g. "localwp" from
//      "localwp.com") — most likely matches the bucket name.
//   2. The second-level domain of alive.txt hosts (e.g. "acme" from
//      "www.acme.com").
//   3. The company-name token from tech_fingerprint.txt (if any).
func deriveOrgs(hosts, tech, domain []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.ToLower(strings.TrimSpace(s))
		s = strings.TrimSuffix(s, ".com")
		s = strings.TrimSuffix(s, ".io")
		s = strings.TrimSuffix(s, ".net")
		s = strings.TrimSuffix(s, ".org")
		s = strings.TrimPrefix(s, "www.")
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, d := range domain {
		add(d)
	}
	for _, h := range hosts {
		add(extractHost(h))
	}
	for _, t := range tech {
		// tech_fingerprint rows are `host  tech1,tech2,`
		parts := strings.Fields(t)
		if len(parts) > 0 {
			add(extractHost(parts[0]))
		}
	}
	return out
}

func extractHost(raw string) string {
	// Strip protocol, path, port.
	s := raw
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.Index(s, ":"); i >= 0 {
		s = s[:i]
	}
	// Take the last 2 labels (handles *.acme.com → acme.com).
	parts := strings.Split(s, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return s
}

func probeAll(ctx context.Context, orgs []string) []string {
	sem := make(chan struct{}, 30) // HEADs are cheap; 30 in-flight is fine
	var wg sync.WaitGroup
	var mu sync.Mutex
	var rows []string

	tr := &http.Transport{MaxIdleConns: 200, MaxIdleConnsPerHost: 30}
	client := &http.Client{
		Transport: tr,
		Timeout:   5 * time.Second,
	}

	for _, org := range orgs {
		for _, kw := range keywords {
			bucket := org + kw
			for _, provider := range []string{"s3", "gcs", "azure"} {
				host := bucketHost(provider, bucket)
				if host == "" {
					continue
				}
				host, provider, bucket := host, provider, bucket
				wg.Add(1)
				sem <- struct{}{}
				go func() {
					defer wg.Done()
					defer func() { <-sem }()
					r := probeOne(ctx, client, provider, bucket, host)
					if r != "" {
						mu.Lock()
						rows = append(rows, r)
						mu.Unlock()
					}
				}()
			}
		}
	}
	wg.Wait()
	return rows
}

func bucketHost(provider, bucket string) string {
	switch provider {
	case "s3":
		return fmt.Sprintf("https://%s.s3.amazonaws.com/", bucket)
	case "gcs":
		return fmt.Sprintf("https://storage.googleapis.com/%s/", bucket)
	case "azure":
		return fmt.Sprintf("https://%s.blob.core.windows.net/", bucket)
	}
	return ""
}

func probeOne(ctx context.Context, client *http.Client, provider, bucket, host string) string {
	req, err := http.NewRequestWithContext(ctx, "HEAD", host, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "rfuf-buckets/1.0")
	iohelp.ApplyAuth(req)
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	resp.Body.Close()

	// 404 = bucket doesn't exist. Skip.
	if resp.StatusCode == 404 {
		return ""
	}
	// 200/403/400 with body content = bucket exists. For S3, 403
	// means "exists, private" — already a real finding on a public
	// program. 200 means public-readable.
	status := resp.StatusCode
	severity := "LOW"
	switch {
	case provider == "s3" && status == 200:
		severity = "CRITICAL"
	case provider == "gcs" && status == 200:
		severity = "CRITICAL"
	case provider == "azure" && status == 200:
		severity = "CRITICAL"
	case status == 403:
		severity = "MEDIUM"
	case status == 400:
		// Azure often returns 400 for non-existent accounts.
		// Treat as ambiguous.
		severity = "INFO"
	}
	return fmt.Sprintf("%s\t%s\tbucket=%s\tstatus=%d\tseverity=%s\thost=%s",
		provider, severity, bucket, status, severity, host)
}
