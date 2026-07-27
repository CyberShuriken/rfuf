package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Stats struct {
	Subdomains int
	LiveSubs   int
	AliveHosts int
	Takeovers  int
	Secrets    int
	Auth       int
	GraphQL    int
	CORS       int
	FFUF       int
	SQLi       int
	XSS        int
	RCE        int
	IDOR       int
	SSRF       int
	Redirect   int
	LFI        int
}

// DrawDashboard uses ANSI "Save Cursor" and "Restore Cursor" to keep the dashboard fixed at the top
func DrawDashboard(domain string, startTime time.Time, steps []string, completed map[string]bool, currentSteps string, stats Stats) {
	// Save cursor position, move to top-left (1,1)
	fmt.Print("\033[s\033[1;1H")
	
	// Clear the lines we're about to write (approx 25 lines for the header)
	for i := 0; i < 25; i++ {
		fmt.Print("\033[2K\n")
	}
	// Move back to top-left
	fmt.Print("\033[1;1H")

	elapsed := time.Since(startTime).Round(time.Second)

	fmt.Println("\033[1;36m┌────────────────────────────────────────────────────────────────────────┐\033[0m")
	fmt.Println("\033[1;36m│ rfuf ─ RECON FASTER U FOOL (Parallel Mode)                             │\033[0m")
	fmt.Printf("\033[1;36m│\033[0m Target: \033[1m%-30s\033[0m | Elapsed: \033[1;33m%-15v\033[0m \033[1;36m│\033[0m\n", domain, elapsed)
	fmt.Println("\033[1;36m├────────────────────────────────────────────────────────────────────────┤\033[0m")
	fmt.Println("\033[1;36m│ LIVE FINDINGS:                                                         │\033[0m")
	fmt.Printf("\033[1;36m│\033[0m Subs: %-5d | Live: %-5d | Alive: %-5d | Takeovers: \033[1;31m%-5d\033[0m       \033[1;36m│\033[0m\n", stats.Subdomains, stats.LiveSubs, stats.AliveHosts, stats.Takeovers)
	fmt.Printf("\033[1;36m│\033[0m Secrets: \033[1;31m%-5d\033[0m | Auth: %-5d | GQL: %-5d | CORS: %-5d | FFUF: %-5d \033[1;36m│\033[0m\n", stats.Secrets, stats.Auth, stats.GraphQL, stats.CORS, stats.FFUF)
	fmt.Printf("\033[1;36m│\033[0m SQLi: %-5d | XSS: %-5d  | RCE: %-5d | IDOR: %-5d | SSRF: %-5d \033[1;36m│\033[0m\n", stats.SQLi, stats.XSS, stats.RCE, stats.IDOR, stats.SSRF)
	fmt.Printf("\033[1;36m│\033[0m Redir: %-5d | LFI: %-5d                                            \033[1;36m│\033[0m\n", stats.Redirect, stats.LFI)
	fmt.Println("\033[1;36m├────────────────────────────────────────────────────────────────────────┤\033[0m")
	fmt.Println("\033[1;36m│ RECENT FINDINGS (Last 3):                                              │\033[0m")
	findings := getRecentFindings(stats)
	for i := 0; i < 3; i++ {
		line := ""
		if i < len(findings) {
			line = findings[i]
		}
		fmt.Printf("\033[1;36m│\033[0m %-70s \033[1;36m│\033[0m\n", line)
	}
	fmt.Println("\033[1;36m├────────────────────────────────────────────────────────────────────────┤\033[0m")
	
	// Progress Bar
	doneCount := 0
	for _, s := range steps {
		if completed[s] {
			doneCount++
		}
	}
	pct := float64(doneCount) / float64(len(steps)) * 100
	barLen := 50
	filledLen := int(float64(barLen) * pct / 100)
	bar := strings.Repeat("█", filledLen) + strings.Repeat("░", barLen-filledLen)
	fmt.Printf("\033[1;36m│\033[0m Progress: [%s] %3.0f%% (%d/%d) \033[1;36m│\033[0m\n", bar, pct, doneCount, len(steps))
	fmt.Println("\033[1;36m└────────────────────────────────────────────────────────────────────────┘\033[0m")

	if currentSteps == "FINISHED" {
		fmt.Println("\n[+] \033[1;32mALL STAGES COMPLETE!\033[0m")
	} else {
		fmt.Printf("\n[*] Active Stages: \033[1;34m%s\033[0m\n", currentSteps)
	}
	fmt.Println(strings.Repeat("─", 74))
	
	// Restore cursor position to continue logging below the dashboard
	fmt.Print("\033[u")
}

func UpdateStats(workDir string) Stats {
	return Stats{
		Subdomains: countLines(filepath.Join(workDir, "subs.txt")),
		LiveSubs:   countLines(filepath.Join(workDir, "live_subs.txt")),
		AliveHosts: countLines(filepath.Join(workDir, "alive.txt")),
		Takeovers:  countLines(filepath.Join(workDir, "validated_takeovers.txt")),
		Secrets:    countLines(filepath.Join(workDir, "trufflehog_results.txt")) + countLines(filepath.Join(workDir, "potential_secrets.txt")),
		Auth:       countLines(filepath.Join(workDir, "auth_results.txt")),
		GraphQL:    countLines(filepath.Join(workDir, "graphql_exposed.txt")),
		CORS:       countLines(filepath.Join(workDir, "cors_findings.txt")),
		FFUF:       countLines(filepath.Join(workDir, "ffuf_dirs_200.txt")),
		SQLi:       countLinesInDir(filepath.Join(workDir, "sqlmap_results")),
		XSS:        countLines(filepath.Join(workDir, "xss_vulnerabilities.txt")),
		RCE:        countLines(filepath.Join(workDir, "nuclei_rce_rce.txt")),
		IDOR:       countLines(filepath.Join(workDir, "idor_vulnerabilities.txt")),
		SSRF:       countLines(filepath.Join(workDir, "ssrf_vulnerabilities.txt")),
		Redirect:   countLines(filepath.Join(workDir, "open_redirect_results.txt")),
		LFI:        countLines(filepath.Join(workDir, "lfi_results.txt")),
	}
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

func getRecentFindings(stats Stats) []string {
	var res []string
	if stats.Takeovers > 0 { res = append(res, fmt.Sprintf("\033[1;31m[!] Subdomain Takeover Found!\033[0m")) }
	if stats.RCE > 0 { res = append(res, fmt.Sprintf("\033[1;31m[!] RCE Vulnerability Found!\033[0m")) }
	if stats.SQLi > 0 { res = append(res, fmt.Sprintf("\033[1;31m[!] SQL Injection Found!\033[0m")) }
	if stats.Secrets > 0 { res = append(res, fmt.Sprintf("\033[1;33m[!] Secrets Exposed!\033[0m")) }
	if stats.XSS > 0 { res = append(res, fmt.Sprintf("\033[1;33m[!] XSS Found!\033[0m")) }
	
	if len(res) == 0 {
		return []string{"Scanning in progress... No critical findings yet."}
	}
	return res
}
