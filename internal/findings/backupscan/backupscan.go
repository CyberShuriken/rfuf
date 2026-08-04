// Package backupscan implements F12: sensitive backup / dotfile /
// developer-artifact probing.
//
// The single highest-yield bug class on most bug-bounty programs:
// exposed `.env`, `.git/config`, `wp-config.php.bak`, `database.sql`,
// `id_rsa`, etc. Most "real" HackerOne reports start from one of
// these URLs — the bug is the file *contents*, not a sophisticated
// exploit.
//
// Methodology: per-host HEAD/GET against a curated list of sensitive
// paths. A 200 (or sometimes 206) on any of these is reported.
//
// Paths are grouped by stack. The module picks the right group based
// on tech_fingerprint.txt (if present) plus a few stack-agnostic
// universal paths (`.env`, `.git/HEAD`, `server-status`, etc.).
//
// Output: backupscan_findings.txt with one row per hit. Format:
//
//	host<TAB>path<TAB>status<TAB>category<TAB>severity
//
// `category` is the path class (env-file, version-control,
// database-dump, ide-tempfile, cloud-credential). Used by the
// hunter to prioritize: cloud-credential > database-dump >
// env-file > version-control > ide-tempfile.
//
// Severity mapping:
//   - env-file, database-dump, cloud-credential   → CRITICAL
//   - version-control (git), ssh-key              → HIGH
//   - admin panel, monitoring endpoint            → MEDIUM
//   - IDE tempfile, OS dotfile (DS_Store)         → LOW
//
// All checks are HEAD-first (cheap). On a 200 response we issue a
// single GET to capture Content-Length and a 16-byte content snippet
// for the report (and to confirm the response is not an empty
// placeholder). The 200 response body is NOT saved — many `.env`
// files contain real production credentials and writing them to a
// findings file risks leakage via the report.
package backupscan

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/CyberShuriken/rfuf/internal/findings/internal/iohelp"
)

// Run is the entry point. workDir is the rfuf work dir.
func Run(workDir string) error {
	hosts, err := iohelp.ReadLines(workDir + "/alive.txt")
	if err != nil {
		return fmt.Errorf("read alive.txt: %w", err)
	}
	if len(hosts) == 0 {
		return iohelp.WriteLines(workDir+"/backupscan_findings.txt", nil)
	}
	const cap = 200
	if len(hosts) > cap {
		hosts = hosts[:cap]
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	// Read tech fingerprint to pick stack-specific paths. Empty file
	// is fine — we fall back to universal paths.
	tech, _ := iohelp.ReadLines(workDir + "/tech_fingerprint.txt")
	paths := buildPathList(tech)

	rows := probeAll(ctx, hosts, paths)
	return iohelp.WriteLines(workDir+"/backupscan_findings.txt", rows)
}

// pathEntry describes one sensitive path to probe.
type pathEntry struct {
	path     string
	category string
	severity string
}

// universalPaths are checked on every host regardless of stack.
var universalPaths = []pathEntry{
	{".env", "env-file", "CRITICAL"},
	{".env.local", "env-file", "CRITICAL"},
	{".env.production", "env-file", "CRITICAL"},
	{".env.backup", "env-file", "CRITICAL"},
	{".git/HEAD", "version-control", "HIGH"},
	{".git/config", "version-control", "HIGH"},
	{".gitignore", "version-control", "LOW"},
	{".svn/entries", "version-control", "HIGH"},
	{".hg/store", "version-control", "HIGH"},
	{".DS_Store", "os-dotfile", "LOW"},
	{".htaccess", "config", "MEDIUM"},
	{".htpasswd", "config", "HIGH"},
	{"backup.zip", "archive", "HIGH"},
	{"backup.tar.gz", "archive", "HIGH"},
	{"backup.sql", "database-dump", "CRITICAL"},
	{"dump.sql", "database-dump", "CRITICAL"},
	{"db.sql", "database-dump", "CRITICAL"},
	{"database.sql", "database-dump", "CRITICAL"},
	{"phpinfo.php", "debug", "MEDIUM"},
	{"info.php", "debug", "MEDIUM"},
	{"server-status", "monitoring", "MEDIUM"},
	{"server-info", "monitoring", "MEDIUM"},
	{"nginx_status", "monitoring", "MEDIUM"},
	{"elmah.axd", "debug", "HIGH"},
	{"trace.axd", "debug", "HIGH"},
	{"id_rsa", "ssh-key", "CRITICAL"},
	{"aws-credentials", "cloud-credential", "CRITICAL"},
	{"credentials.json", "cloud-credential", "CRITICAL"},
	{".aws/credentials", "cloud-credential", "CRITICAL"},
	{"crossdomain.xml", "config", "LOW"},
	{"robots.txt", "config", "INFO"},
	{"sitemap.xml", "config", "INFO"},
	{"wp-config.php.bak", "config", "CRITICAL"},
	{"config.php.bak", "config", "CRITICAL"},
	{".vscode/sftp.json", "ide-config", "MEDIUM"},
	{".idea/workspace.xml", "ide-config", "LOW"},
	{"web.config", "config", "INFO"},
}

// stackPaths adds stack-specific paths when tech_fingerprint.txt
// identifies the stack.
func stackPaths(tech []string) []pathEntry {
	var out []pathEntry
	hasWordpress := false
	hasLaravel := false
	hasNode := false
	for _, line := range tech {
		l := strings.ToLower(line)
		if strings.Contains(l, "wordpress") {
			hasWordpress = true
		}
		if strings.Contains(l, "laravel") || strings.Contains(l, "livewire") {
			hasLaravel = true
		}
		if strings.Contains(l, "nextjs") || strings.Contains(l, "next.js") {
			hasNode = true
		}
	}
	if hasWordpress {
		out = append(out,
			pathEntry{"wp-config.php", "config", "HIGH"},
			pathEntry{"wp-config.php~", "config", "CRITICAL"},
			pathEntry{"wp-config.php.old", "config", "CRITICAL"},
			pathEntry{"wp-config.php.save", "config", "CRITICAL"},
			pathEntry{"wp-config.php.swp", "config", "CRITICAL"},
			pathEntry{"wp-config.bak", "config", "CRITICAL"},
			pathEntry{"xmlrpc.php", "service", "MEDIUM"},
			pathEntry{"wp-content/debug.log", "log", "MEDIUM"},
			pathEntry{"wp-includes/version.php", "version", "INFO"},
			pathEntry{".wp-config.php.swp", "config", "CRITICAL"},
		)
	}
	if hasLaravel {
		out = append(out,
			pathEntry{".env.example", "config", "INFO"},
			pathEntry{".env.testing", "env-file", "CRITICAL"},
			pathEntry{"storage/logs/laravel.log", "log", "MEDIUM"},
			pathEntry{"storage/debugbar", "debug", "MEDIUM"},
		)
	}
	if hasNode {
		out = append(out,
			pathEntry{"yarn-error.log", "log", "MEDIUM"},
			pathEntry{"npm-debug.log", "log", "MEDIUM"},
			pathEntry{".npmrc", "config", "MEDIUM"},
			pathEntry{".yarnrc", "config", "MEDIUM"},
			pathEntry{".env.development", "env-file", "CRITICAL"},
		)
	}
	return out
}

// buildPathList merges universal paths with stack-specific ones and
// dedups. Order matters for stable output — universal first.
func buildPathList(tech []string) []pathEntry {
	seen := map[string]bool{}
	var out []pathEntry
	for _, p := range universalPaths {
		if !seen[p.path] {
			seen[p.path] = true
			out = append(out, p)
		}
	}
	for _, p := range stackPaths(tech) {
		if !seen[p.path] {
			seen[p.path] = true
			out = append(out, p)
		}
	}
	return out
}

func probeAll(ctx context.Context, hosts []string, paths []pathEntry) []string {
	sem := make(chan struct{}, 30) // HEAD is cheap
	var wg sync.WaitGroup
	var mu sync.Mutex
	var out []string

	tr := &http.Transport{MaxIdleConns: 200, MaxIdleConnsPerHost: 30}
	client := &http.Client{
		Transport: tr,
		Timeout:   6 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, h := range hosts {
		h := h
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			rs := probeHost(ctx, client, h, paths)
			if len(rs) > 0 {
				mu.Lock()
				out = append(out, rs...)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return out
}

func probeHost(ctx context.Context, client *http.Client, host string, paths []pathEntry) []string {
	var out []string
	for _, p := range paths {
		// Build the URL. host already has scheme + host + optional path.
		url := strings.TrimRight(host, "/") + "/" + p.path

		req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "rfuf-backupscan/1.0")
		iohelp.ApplyAuth(req)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		status := resp.StatusCode
		resp.Body.Close()

		if status < 200 || status >= 300 {
			continue
		}
		// On 200/2xx, do a single GET to capture Content-Length and
		// 16-byte content snippet. We do NOT write the body to disk.
		cl, snippet := verifyGet(ctx, client, url)
		out = append(out, fmt.Sprintf("%s\t%s\t%d\t%s\t%s\tlen=%d\tsnippet=%q",
			host, p.path, status, p.category, p.severity, cl, snippet))
	}
	return out
}

func verifyGet(ctx context.Context, client *http.Client, url string) (int, string) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, ""
	}
	req.Header.Set("User-Agent", "rfuf-backupscan/1.0")
	iohelp.ApplyAuth(req)
	resp, err := client.Do(req)
	if err != nil {
		return 0, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	var cl int
	if resp.ContentLength > 0 {
		cl = int(resp.ContentLength)
	} else {
		cl = len(body)
	}
	// First 16 bytes as snippet — must be printable to be useful
	// (env files start with "APP_NAME=", .git/HEAD starts with
	// "ref:", etc.).
	snippet := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return r
		}
		if r < 32 || r > 126 {
			return '.'
		}
		return r
	}, string(body))
	if len(snippet) > 16 {
		snippet = snippet[:16]
	}
	return cl, snippet
}