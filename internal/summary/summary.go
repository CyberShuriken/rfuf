package summary

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CyberShuriken/rfuf/internal/checkpoint"
)

func Generate(workDir string, cp *checkpoint.Checkpoint) error {
	duration := cp.LastUpdated.Sub(cp.StartedAt)
	
	subdomains := countLines(filepath.Join(workDir, "subs.txt"))
	liveSubs := countLines(filepath.Join(workDir, "live_subs.txt"))
	aliveHosts := countLines(filepath.Join(workDir, "alive.txt"))
	takeovers := countLines(filepath.Join(workDir, "validated_takeovers.txt"))
	secrets := countLines(filepath.Join(workDir, "trufflehog_results.txt")) + countLines(filepath.Join(workDir, "potential_secrets.txt"))
	
	sqli := countLines(filepath.Join(workDir, "sqli_targets.txt"))
	xss := countLines(filepath.Join(workDir, "xss_targets.txt"))
	rce := countLines(filepath.Join(workDir, "rce_targets.txt"))
	idor := countLines(filepath.Join(workDir, "idor_targets.txt"))
	
	// V2 stats
	auth := countLines(filepath.Join(workDir, "auth_results.txt"))
	graphql := countLines(filepath.Join(workDir, "graphql_exposed.txt"))
	ssrf := countLines(filepath.Join(workDir, "ssrf_vulnerabilities.txt"))
	redirect := countLines(filepath.Join(workDir, "open_redirect_results.txt"))
	lfi := countLines(filepath.Join(workDir, "lfi_results.txt"))
	cors := countLines(filepath.Join(workDir, "cors_findings.txt"))
	ffuf := countLines(filepath.Join(workDir, "ffuf_dirs_200.txt"))

	content := fmt.Sprintf(`# RFUF Scan Summary for %s

- **Scan Started:** %s
- **Scan Finished:** %s
- **Total Duration:** %v

## Recon Stats
- **Total Subdomains:** %d
- **Live Subdomains (DNS):** %d
- **Alive HTTP Hosts:** %d

## Findings
- **Confirmed Takeovers:** %d
- **Potential Secrets:** %d
- **Auth/JWT Issues:** %d
- **GraphQL Exposed:** %d
- **CORS Misconfigurations:** %d
- **Hidden Directories (FFUF):** %d

## Vulnerability Targets & Results
- **SQLi Candidates:** %d
- **XSS Candidates:** %d
- **RCE Candidates:** %d
- **IDOR Candidates:** %d
- **SSRF Findings:** %d
- **Open Redirect Findings:** %d
- **LFI Findings:** %d

## Next Steps for Manual Review
- [ ] Review `+"`"+`validated_takeovers.txt`+"`"+` for high-confidence subdomain takeovers.
- [ ] Inspect `+"`"+`trufflehog_results.txt`+"`"+` for verified API keys.
- [ ] Check `+"`"+`sqlmap_results/`+"`"+` for any successful injections.
- [ ] Manually verify XSS findings in `+"`"+`xss_vulnerabilities.txt`+"`"+`.
- [ ] Analyze `+"`"+`manual_business_logic_review.txt`+"`"+` for sensitive endpoints (checkout, payment, etc.).
- [ ] Review FFUF discovered paths in `+"`"+`ffuf_dirs_200.txt`+"`"+`.
`, cp.Domain, cp.StartedAt.Format(time.RFC822), cp.LastUpdated.Format(time.RFC822), duration, 
	subdomains, liveSubs, aliveHosts, takeovers, secrets, auth, graphql, cors, ffuf,
	sqli, xss, rce, idor, ssrf, redirect, lfi)

	return os.WriteFile(filepath.Join(workDir, "SUMMARY.md"), []byte(content), 0644)
}

func countLines(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return 0
	}
	return len(lines)
}
