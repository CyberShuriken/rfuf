package envsecrets

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/CyberShuriken/rfuf/internal/findings/internal/iohelp"
)

var secretRegexes = map[string]*regexp.Regexp{
	"AWS":       regexp.MustCompile(`(?i)(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)\s*=\s*["']?([A-Za-z0-9/+=]{16,})["']?`),
	"Stripe":    regexp.MustCompile(`(?i)(STRIPE_KEY|STRIPE_SECRET|STRIPE_PUBLISHABLE)\s*=\s*["']?([a-zA-Z0-9_]{24,})["']?`),
	"Database":  regexp.MustCompile(`(?i)(DB_PASSWORD|DATABASE_URL|POSTGRES_PASSWORD|MYSQL_ROOT_PASSWORD|MONGODB_URI)\s*=\s*["']?([^"'\s]+)["']?`),
	"Azure":     regexp.MustCompile(`(?i)(AZURE_CLIENT_SECRET|AZURE_CLIENT_ID|AZURE_TENANT_ID)\s*=\s*["']?([^"'\s]+)["']?`),
	"GCP":       regexp.MustCompile(`(?i)(GOOGLE_APPLICATION_CREDENTIALS|GCP_PROJECT_ID|GCP_SERVICE_ACCOUNT)\s*=\s*["']?([^"'\s]+)["']?`),
	"General":   regexp.MustCompile(`(?i)(SECRET|PASSWORD|API_KEY|TOKEN|AUTH_TOKEN|SIGNING_KEY)\s*=\s*["']?([A-Za-z0-9/+=_-]{16,})["']?`),
}

// Run reads identified 200 OK URLs, fetches those that look like sensitive config files, and extracts secrets.
func Run(workDir string) error {
	urls, err := iohelp.ReadLines(workDir + "/ffuf_dirs_200.txt")
	if err != nil {
		// fall back to all_urls_200.txt
		urls, err = iohelp.ReadLines(workDir + "/all_urls_200.txt")
		if err != nil {
			return iohelp.WriteLines(workDir+"/env_secrets.txt", []string{})
		}
	}

	var findings []string
	extensions := []string{".env", ".env.bak", ".env.local", ".env.old", ".bak", ".old", ".swp", ".zip", ".sql", ".git/config"}

	for _, urlStr := range urls {
		isSensitive := false
		for _, ext := range extensions {
			if strings.Contains(urlStr, ext) {
				isSensitive = true
				break
			}
		}
		if !isSensitive {
			continue
		}

		// Fetch the file
		content, err := fetchURL(urlStr)
		if err != nil {
			continue
		}

		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			for label, re := range secretRegexes {
				matches := re.FindStringSubmatch(line)
				if len(matches) >= 3 {
					findings = append(findings, fmt.Sprintf("[%s] %s: %s=%s", label, urlStr, matches[1], matches[2]))
					break
				}
			}
		}
	}

	return iohelp.WriteLines(workDir+"/env_secrets.txt", findings)
}

func fetchURL(urlStr string) ([]byte, error) {
	// Basic fetch implementation
	resp, err := http.Get(urlStr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("bad status: %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

