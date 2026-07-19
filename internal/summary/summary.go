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

## Vulnerability Targets
- **SQLi Candidates:** %d
- **XSS Candidates:** %d
- **RCE Candidates:** %d
- **IDOR Candidates:** %d

## Next Steps for Manual Review
- [ ] Review `+"`"+`validated_takeovers.txt`+"`"+` for high-confidence subdomain takeovers.
- [ ] Inspect `+"`"+`trufflehog_results.txt`+"`"+` for verified API keys.
- [ ] Check `+"`"+`sqlmap_results/`+"`"+` for any successful injections.
- [ ] Manually verify XSS findings in `+"`"+`xss_vulnerabilities.txt`+"`"+`.
`, cp.Domain, cp.StartedAt.Format(time.RFC822), cp.LastUpdated.Format(time.RFC822), duration, 
	subdomains, liveSubs, aliveHosts, takeovers, secrets, sqli, xss, rce, idor)

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
