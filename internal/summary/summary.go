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

	// Basic Stats
	subdomains := countLines(filepath.Join(workDir, "subs.txt"))
	liveSubs := countLines(filepath.Join(workDir, "live_subs.txt"))
	aliveHosts := countLines(filepath.Join(workDir, "alive.txt"))

	// Vulnerability Data
	takeovers := getFileContent(filepath.Join(workDir, "validated_takeovers.txt"))
	secrets := getFileContent(filepath.Join(workDir, "trufflehog_results.txt"))
	potentialSecrets := getFileContent(filepath.Join(workDir, "potential_secrets.txt"))
	auth := getFileContent(filepath.Join(workDir, "auth_results.txt"))
	graphql := getFileContent(filepath.Join(workDir, "graphql_exposed.txt"))
	ssrf := getFileContent(filepath.Join(workDir, "ssrf_vulnerabilities.txt"))
	redirect := getFileContent(filepath.Join(workDir, "open_redirect_results.txt"))
	lfi := getFileContent(filepath.Join(workDir, "lfi_results.txt"))
	cors := getFileContent(filepath.Join(workDir, "cors_findings.txt"))
	xss := getFileContent(filepath.Join(workDir, "xss_vulnerabilities.txt"))
	rce := getFileContent(filepath.Join(workDir, "nuclei_rce_rce.txt"))
	idor := getFileContent(filepath.Join(workDir, "idor_vulnerabilities.txt"))
	ffuf := getFileContent(filepath.Join(workDir, "ffuf_dirs_200.txt"))

	// Generate overall_findings.md (High, Medium, Critical)
	var findings strings.Builder
	findings.WriteString(fmt.Sprintf("# Detailed Findings for %s\n\n", cp.Domain))
	findings.WriteString(fmt.Sprintf("Generated at: %s\n\n", time.Now().Format(time.RFC822)))

	addFindingSection(&findings, "Critical: RCE Findings", rce, "Potential Remote Code Execution detected by Nuclei.")
	addFindingSection(&findings, "High: Subdomain Takeovers", takeovers, "Confirmed subdomain takeovers. High priority for manual verification.")
	addFindingSection(&findings, "High: LFI Findings", lfi, "Potential Local File Inclusion detected.")
	addFindingSection(&findings, "High: SSRF Findings", ssrf, "Potential Server Side Request Forgery detected.")
	addFindingSection(&findings, "High: Verified Secrets", secrets, "API keys and secrets verified by TruffleHog.")
	addFindingSection(&findings, "Medium: XSS Vulnerabilities", xss, "Potential Cross-Site Scripting findings.")
	addFindingSection(&findings, "Medium: Auth & JWT Issues", auth, "Potential authentication bypass or JWT misconfigurations.")
	addFindingSection(&findings, "Medium: IDOR Findings", idor, "Potential Insecure Direct Object Reference detected.")
	addFindingSection(&findings, "Medium: Open Redirects", redirect, "Potential Open Redirect vulnerabilities.")
	addFindingSection(&findings, "Low: GraphQL Exposure", graphql, "Exposed GraphQL endpoints found.")
	addFindingSection(&findings, "Low: CORS Misconfigurations", cors, "CORS misconfigurations that may allow cross-origin data access.")
	addFindingSection(&findings, "Info: Potential Secrets (Grep)", potentialSecrets, "Keywords like 'api_key' or 'secret' found in URLs.")
	addFindingSection(&findings, "Info: Hidden Directories (FFUF)", ffuf, "Interesting directories found during brute-force.")

	os.WriteFile(filepath.Join(workDir, "overall_findings.md"), []byte(findings.String()), 0644)

	// Generate SUMMARY.md
	summary := fmt.Sprintf(`# RFUF Scan Summary for %s

- **Scan Started:** %s
- **Scan Finished:** %s
- **Total Duration:** %v

## Recon Stats
- **Total Subdomains:** %d
- **Live Subdomains (DNS):** %d
- **Alive HTTP Hosts:** %d

## Vulnerability Overview
- **RCE:** %d
- **Takeovers:** %d
- **LFI:** %d
- **SSRF:** %d
- **XSS:** %d
- **SQLi (Check sqlmap_results/):** %d
- **Secrets:** %d
- **Auth/JWT:** %d
- **CORS:** %d
- **FFUF:** %d

Detailed findings have been saved to [overall_findings.md](./overall_findings.md).
`, cp.Domain, cp.StartedAt.Format(time.RFC822), cp.LastUpdated.Format(time.RFC822), duration,
		subdomains, liveSubs, aliveHosts,
		len(rce), len(takeovers), len(lfi), len(ssrf), len(xss), countLinesInDir(filepath.Join(workDir, "sqlmap_results")),
		len(secrets)+len(potentialSecrets), len(auth), len(cors), len(ffuf))

	return os.WriteFile(filepath.Join(workDir, "SUMMARY.md"), []byte(summary), 0644)
}

func addFindingSection(sb *strings.Builder, title string, items []string, desc string) {
	if len(items) == 0 {
		return
	}
	sb.WriteString(fmt.Sprintf("## %s\n", title))
	sb.WriteString(fmt.Sprintf("> %s\n\n", desc))
	for _, item := range items {
		sb.WriteString(fmt.Sprintf("- %s\n", item))
	}
	sb.WriteString("\n")
}

func getFileContent(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return []string{}
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var result []string
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			result = append(result, line)
		}
	}
	return result
}

func countLines(path string) int {
	return len(getFileContent(path))
}

func countLinesInDir(path string) int {
	files, err := os.ReadDir(path)
	if err != nil {
		return 0
	}
	count := 0
	for _, f := range files {
		if !f.IsDir() {
			count++
		}
	}
	return count
}
