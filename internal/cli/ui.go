package cli

import (
	"fmt"
	"os"
	"os/exec"
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
}

// DrawDashboard builds the entire UI string in memory and prints it atomically
func DrawDashboard(domain string, startTime time.Time, steps []string, completed map[string]bool, currentStep string, stats Stats, workDir string) {
	var b strings.Builder
	
	// ANSI Escape: Move to top-left and clear from cursor to end of screen
	// This is much more robust than clearing the whole screen buffer
	b.WriteString("\033[H\033[J")
	
	elapsed := time.Since(startTime).Round(time.Second)

	b.WriteString("┌────────────────────────────────────────────────────────────────────────┐\n")
	b.WriteString("│ rfuf ─ RECON FASTER U FOOL                                            │\n")
	b.WriteString(fmt.Sprintf("│ Target: %-30s | Elapsed: %-15v │\n", domain, elapsed))
	b.WriteString("├────────────────────────────────────────────────────────────────────────┤\n")
	b.WriteString("│ LIVE STATS:                                                            │\n")
	b.WriteString(fmt.Sprintf("│ Subs: %-5d | Live: %-5d | Alive: %-5d | Takeovers: %-5d       │\n", stats.Subdomains, stats.LiveSubs, stats.AliveHosts, stats.Takeovers))
	b.WriteString(fmt.Sprintf("│ Secrets: %-5d | Auth: %-5d | GQL: %-5d | CORS: %-5d | FFUF: %-5d │\n", stats.Secrets, stats.Auth, stats.GraphQL, stats.CORS, stats.FFUF))
	b.WriteString("└────────────────────────────────────────────────────────────────────────┘\n")

	// Draw steps in 2 columns
	for i := 0; i < len(steps); i += 2 {
		line := ""
		for j := 0; j < 2; j++ {
			if i+j < len(steps) {
				s := steps[i+j]
				status := "  "
				if completed[s] {
					status = "\033[32m✔\033[0m " // Green check
				} else if s == currentStep {
					status = "\033[34m→\033[0m " // Blue arrow
				} else {
					status = "○ "
				}
				
				name := s
				if len(name) > 25 {
					name = name[:22] + "..."
				}
				
				item := fmt.Sprintf("%s %-28s", status, name)
				line += item
			}
		}
		b.WriteString(line + "\n")
	}
	
	b.WriteString("\n" + strings.Repeat("─", 74) + "\n")
	b.WriteString(fmt.Sprintf("[*] Current Step: \033[1m%s\033[0m\n", currentStep))
	b.WriteString("\nLive Log (last 5 lines):\n")
	b.WriteString(GetLiveLog(workDir, 5))
	
	// Final atomic print to terminal
	fmt.Print(b.String())
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

func GetLiveLog(workDir string, lines int) string {
	logPath := filepath.Join(workDir, ".rfuf", "rfuf.log")
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		return "(no log yet)\n"
	}
	cmd := exec.Command("tail", "-n", fmt.Sprintf("%d", lines), logPath)
	out, _ := cmd.Output()
	return string(out)
}
