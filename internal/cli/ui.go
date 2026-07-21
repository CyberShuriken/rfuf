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

func ClearScreen() {
	fmt.Print("\033[H\033[2J")
}

func DrawDashboard(domain string, startTime time.Time, steps []string, completed map[string]bool, currentStep string, stats Stats) {
	ClearScreen()
	elapsed := time.Since(startTime).Round(time.Second)

	fmt.Println("┌────────────────────────────────────────────────────────────────────────┐")
	fmt.Printf("│ rfuf ─ RECON FASTER U FOOL                                            │\n")
	fmt.Printf("│ Target: %-30s | Elapsed: %-15v │\n", domain, elapsed)
	fmt.Println("├────────────────────────────────────────────────────────────────────────┤")
	fmt.Printf("│ LIVE STATS:                                                            │\n")
	fmt.Printf("│ Subs: %-5d | Live: %-5d | Alive: %-5d | Takeovers: %-5d       │\n", stats.Subdomains, stats.LiveSubs, stats.AliveHosts, stats.Takeovers)
	fmt.Printf("│ Secrets: %-5d | Auth: %-5d | GQL: %-5d | CORS: %-5d | FFUF: %-5d │\n", stats.Secrets, stats.Auth, stats.GraphQL, stats.CORS, stats.FFUF)
	fmt.Println("└────────────────────────────────────────────────────────────────────────┘")

	// Draw steps in 2 columns
	for i := 0; i < len(steps); i += 2 {
		line := ""
		for j := 0; j < 2; j++ {
			if i+j < len(steps) {
				s := steps[i+j]
				status := "  "
				if completed[s] {
					status = "✔ "
				} else if s == currentStep {
					status = "→ "
				} else {
					status = "○ "
				}
				
				// Truncate step name if too long
				name := s
				if len(name) > 25 {
					name = name[:22] + "..."
				}
				
				item := fmt.Sprintf("%s %-28s", status, name)
				line += item
			}
		}
		fmt.Println(line)
	}
	fmt.Println("\n" + strings.Repeat("─", 74))
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
	cmd := exec.Command("tail", "-n", fmt.Sprintf("%d", lines), logPath)
	out, _ := cmd.Output()
	return string(out)
}
