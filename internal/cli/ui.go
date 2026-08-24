package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CyberShuriken/rfuf/internal/coverage"
	"github.com/CyberShuriken/rfuf/internal/summary"
)

// Stats is the snapshot of finding counts the dashboard renders. Each
// metric corresponds to an output file the pipeline produces; if the file
// is missing, the count reads as zero without erroring the dashboard.
type Stats struct {
	Subdomains      int
	LiveSubs        int
	AliveHosts      int
	Takeovers       int
	Secrets         int
	Auth            int
	GraphQL         int
	CORS            int
	FFUF            int
	SQLi            int
	XSS             int
	RCE             int
	IDOR            int
	SSRF            int
	Redirect        int
	LFI             int
	WAFDetected     int
	OpenPorts       int
	HiddenParams    int
	GhauriSQLi      int
	CoverageStatus  string
	TotalStages     int
	CompletedStages int
	FailedStages    int
	TimedOutStages  int
	SkippedStages   int
	BlockedStages   int
}

// altScreenSupported is computed once on first use (windows console,
// emulators without DECTCEM, "dumb" terms, RFUF_NO_TUI=1 → fallback).
// The alt-screen buffer keeps our dashboard separate from the user's
// shell scrollback — without it, every nfuf write scrolls the user's
// previous output and produces the "duplicate frame" effect called out
// in the rfuf-tui-dashboard memory.
var (
	altScreenOnce   sync.Once
	altScreenOK     atomic.Bool
	altScreenActive atomic.Bool
	logRing         []string
	logRingMu       sync.Mutex
	maxLogRingLines           = 6
	outWriter       io.Writer = os.Stdout
)

// useAltScreen decides once whether the terminal supports the alt-screen
// buffer. Returns false on "dumb" $TERM, when stdout isn't a tty, or when
// the user opts out via RFUF_NO_TUI=1. The TODO ioctl IsTerminal check from
// the memory lives here too — implemented via os.Stat + stdin's tty-ness
// check, since importing x/syscall for ioctl just for this is overkill.
func useAltScreen() bool {
	altScreenOnce.Do(func() {
		if os.Getenv("RFUF_NO_TUI") == "1" {
			return
		}
		if strings.EqualFold(os.Getenv("TERM"), "dumb") {
			return
		}
		// Stat stdout: if ModeCharDevice is set, it's a tty.
		fi, err := os.Stdout.Stat()
		if err != nil || (fi.Mode()&os.ModeCharDevice) == 0 {
			return
		}
		altScreenOK.Store(true)
	})
	return altScreenOK.Load()
}

// StartDashboard enters the alt-screen buffer (if supported) and hides
// the cursor. Pair every successful StartDashboard with StopDashboard or
// the user's terminal will be left in a broken state on exit.
func StartDashboard() {
	if !useAltScreen() {
		return
	}
	if altScreenActive.Load() {
		return
	}
	fmt.Fprint(outWriter, "\033[?1049h\033[?25l")
	altScreenActive.Store(true)
}

// StopDashboard leaves the alt-screen buffer (restoring prior scrollback)
// and re-shows the cursor. Safe to call even if StartDashboard was
// skipped (no-op in that case).
func StopDashboard() {
	if !altScreenActive.Load() {
		return
	}
	fmt.Fprint(outWriter, "\033[?25h\033[?1049l")
	altScreenActive.Store(false)
}

// PushLogLine is invoked by the executor's throttled log callback for
// every Nth child-process output line. We keep a tiny ring buffer so the
// dashboard's "Recent Activity" section can show the last few tool lines
// without doing file I/O every render.
func sanitizeDashboardLine(line string) string {
	line = strings.TrimSpace(line)
	if strings.Contains(line, "Templates:") && strings.Contains(line, "Requests:") {
		return "[scanner statistics recorded in .rfuf/rfuf.log]"
	}
	for _, marker := range []string{"Authorization:", "Cookie:", "X-Bug-Bounty:", "X-HackerOne-Research:", "X-Test-Account-Email:"} {
		if strings.Contains(line, marker) {
			return "[redacted request metadata; see stage status files]"
		}
	}
	return line
}

func PushLogLine(line string) {
	logRingMu.Lock()
	defer logRingMu.Unlock()
	logRing = append(logRing, sanitizeDashboardLine(line))
	if len(logRing) > maxLogRingLines {
		logRing = logRing[len(logRing)-maxLogRingLines:]
	}
}

func currentLogRing() []string {
	logRingMu.Lock()
	defer logRingMu.Unlock()
	out := make([]string, len(logRing))
	copy(out, logRing)
	return out
}

// SetOutput allows tests to redirect the dashboard's writes to a buffer.
// Defaults to os.Stdout. Always set this BEFORE StartDashboard.
func SetOutput(w io.Writer) {
	outWriter = w
}

// DrawDashboard renders a single, complete dashboard frame to outWriter.
//
// Implementation follows the rfuf-tui-dashboard memory:
//   - Build the entire frame in a strings.Builder; one io.WriteString
//     call to outWriter. Never mix fmt.Print with the rendered frame.
//   - Save cursor + position to (1,1) + use alt-screen, so prior
//     scrollback never mixes with dashboard output.
//   - Pad with a lenNoEsc helper so ANSI escapes don't break alignment.
//
// This function deliberately does NOT use the alt-screen ANSI itself —
// that's StartDashboard's job. The memory rule is "single render thread"
// and this is the only place that writes dashboard content, so the rule
// is satisfied structurally; concurrent stages cannot call DrawDashboard
// because they only mutate state which the ticker loop reads.
func DrawDashboard(domain string, startTime time.Time, steps []string, completed map[string]bool, currentSteps string, stats Stats) {
	elapsed := time.Since(startTime).Round(time.Second)
	rows := buildDashboardRows(domain, elapsed, steps, completed, currentSteps, stats)

	var sb strings.Builder
	// Position to top-left and clear the dashboard region.
	sb.WriteString("\033[1;1H")
	for i := 0; i < 30; i++ {
		sb.WriteString("\033[2K\n")
	}
	sb.WriteString("\033[1;1H")

	const width = 74
	border := "\033[1;36m" + strings.Repeat("─", width-2) + "\033[0m"
	sb.WriteString("\033[1;36m┌" + border + "┐\033[0m\n")
	for _, r := range rows {
		sb.WriteString("\033[1;36m│\033[0m ")
		sb.WriteString(padNoEsc(r, width-4))
		sb.WriteString(" \033[1;36m│\033[0m\n")
	}
	sb.WriteString("\033[1;36m└" + border + "┘\033[0m\n")
	if currentSteps == "FINISHED" {
		sb.WriteString("\n[+] \033[1;32mALL STAGES COMPLETE!\033[0m\n")
	} else {
		sb.WriteString(fmt.Sprintf("\n[*] Active Stages: \033[1;34m%s\033[0m\n", currentSteps))
	}
	sb.WriteString(strings.Repeat("─", width) + "\n")

	io.WriteString(outWriter, sb.String())
}

// buildDashboardRows returns each row of the dashboard, with embedded
// ANSI escapes (for color), pre-formatted. Visible-character accounting
// is taken care of in padNoEsc.
func buildDashboardRows(domain string, elapsed time.Duration, steps []string, completed map[string]bool, currentSteps string, stats Stats) []string {
	rows := []string{
		"\033[1;36mrfuf ─ RECON FASTER U FOOL (Parallel Mode)\033[0m",
		fmt.Sprintf("Target: \033[1m%-30s\033[0m | Elapsed: \033[1;33m%-15v\033[0m", domain, elapsed),
		"\033[1;36mLIVE FINDINGS:\033[0m",
		fmt.Sprintf("Subs: %-5d | Live: %-5d | Alive: %-5d | Takeovers: \033[1;31m%-5d\033[0m",
			stats.Subdomains, stats.LiveSubs, stats.AliveHosts, stats.Takeovers),
		fmt.Sprintf("Secrets: \033[1;31m%-5d\033[0m | Auth: %-5d | GQL: %-5d | CORS: %-5d | FFUF: %-5d",
			stats.Secrets, stats.Auth, stats.GraphQL, stats.CORS, stats.FFUF),
		fmt.Sprintf("SQLi: %-5d | Ghauri: %-4d | RCE: %-4d | IDOR: %-4d | SSRF: %-4d",
			stats.SQLi, stats.GhauriSQLi, stats.RCE, stats.IDOR, stats.SSRF),
		fmt.Sprintf("XSS: %-5d | Redir: %-4d | LFI: %-4d | WAF: %-4d | Ports: %-4d",
			stats.XSS, stats.Redirect, stats.LFI, stats.WAFDetected, stats.OpenPorts),
		fmt.Sprintf("Hidden Params: %-4d", stats.HiddenParams),
		fmt.Sprintf("Health: %s | Stages %d/%d | Failed %d | Timeout %d | Skipped %d | Blocked %d", stats.CoverageStatus, stats.CompletedStages, stats.TotalStages, stats.FailedStages, stats.TimedOutStages, stats.SkippedStages, stats.BlockedStages),
		"\033[1;36mRECENT FINDINGS (Last 3):\033[0m",
	}
	for _, f := range getRecentFindings(stats) {
		rows = append(rows, f)
	}
	for len(rows) < 12 {
		rows = append(rows, "")
	}

	rows = append(rows, "\033[1;36mRECENT LOG LINES (Last 6):\033[0m")
	logLines := currentLogRing()
	combined := logLines
	// If we have no log lines yet (very start of scan), pad with hint.
	for len(combined) < maxLogRingLines {
		combined = append([]string{""}, combined...)
	}
	if len(combined) > maxLogRingLines {
		combined = combined[len(combined)-maxLogRingLines:]
	}
	for _, l := range combined {
		rows = append(rows, l)
	}

	// Progress row.
	doneCount := 0
	for _, s := range steps {
		if completed[s] {
			doneCount++
		}
	}
	pct := float64(doneCount) / float64(len(steps)) * 100
	barLen := 50
	filledLen := int(float64(barLen) * pct / 100)
	if filledLen < 0 {
		filledLen = 0
	}
	if filledLen > barLen {
		filledLen = barLen
	}
	bar := strings.Repeat("█", filledLen) + strings.Repeat("░", barLen-filledLen)
	rows = append(rows, fmt.Sprintf("Progress: [%s] %3.0f%% (%d/%d)", bar, pct, doneCount, len(steps)))
	return rows
}

// padNoEsc pads s with spaces so the visible character count == width.
// Visible = len(s) minus ANSI escape sequences "\033[...\033[0m". Without
// this, a red-coloured "Subs: 5" counts as 11 instead of 6 and breaks
// the right-side border alignment (the original dashboard had this bug).
func padNoEsc(s string, width int) string {
	visible := lenNoEsc(s)
	if visible >= width {
		return s
	}
	return s + strings.Repeat(" ", width-visible)
}

func lenNoEsc(s string) int {
	n := 0
	inEsc := false
	for _, r := range s {
		if r == 0x1b {
			inEsc = true
			continue
		}
		if inEsc {
			if r == 'm' {
				inEsc = false
			}
			continue
		}
		n++
	}
	return n
}

func UpdateStats(workDir string) Stats {
	stats := Stats{
		Subdomains:     countLines(filepath.Join(workDir, "subs.txt")),
		LiveSubs:       countLines(filepath.Join(workDir, "live_subs.txt")),
		AliveHosts:     countLines(filepath.Join(workDir, "alive.txt")),
		Takeovers:      countLines(filepath.Join(workDir, "validated_takeovers.txt")),
		Secrets:        countLines(filepath.Join(workDir, "trufflehog_results.txt")) + countLines(filepath.Join(workDir, "potential_secrets.txt")),
		Auth:           countLines(filepath.Join(workDir, "auth_results.txt")),
		GraphQL:        countLines(filepath.Join(workDir, "graphql_exposed.txt")),
		CORS:           countLines(filepath.Join(workDir, "cors_findings.txt")),
		FFUF:           countLines(filepath.Join(workDir, "ffuf_dirs_200.txt")),
		SQLi:           summary.ConfirmedSqlmapCount(filepath.Join(workDir, "sqlmap_results")),
		XSS:            countLines(filepath.Join(workDir, "xss_vulnerabilities.txt")),
		RCE:            countLines(filepath.Join(workDir, "nuclei_rce_rce.txt")),
		IDOR:           countLines(filepath.Join(workDir, "idor_vulnerabilities.txt")),
		SSRF:           countLines(filepath.Join(workDir, "ssrf_vulnerabilities.txt")),
		Redirect:       countLines(filepath.Join(workDir, "open_redirect_results.txt")),
		LFI:            countLines(filepath.Join(workDir, "lfi_results.txt")),
		WAFDetected:    countLines(filepath.Join(workDir, "waf_detections.txt")),
		OpenPorts:      countLines(filepath.Join(workDir, "naabu_ports.txt")),
		HiddenParams:   countLines(filepath.Join(workDir, "hidden_params.txt")),
		GhauriSQLi:     countLines(filepath.Join(workDir, "ghauri_results.txt")),
		CoverageStatus: "UNKNOWN",
	}
	if records, err := coverage.LoadStageRecords(workDir); err == nil && len(records) > 0 {
		stats.TotalStages = len(records)
		stats.CoverageStatus = "RUNNING"
		for _, record := range records {
			switch record.Status {
			case coverage.StatusCompleted, coverage.StatusCompletedEmpty:
				stats.CompletedStages++
			case coverage.StatusFailed:
				stats.FailedStages++
			case coverage.StatusTimedOut:
				stats.TimedOutStages++
			case coverage.StatusSkipped:
				stats.SkippedStages++
			case coverage.StatusBlocked:
				stats.BlockedStages++
			}
		}
		if stats.FailedStages > 0 || stats.TimedOutStages > 0 || stats.SkippedStages > 0 || stats.BlockedStages > 0 {
			stats.CoverageStatus = "INCOMPLETE"
		} else if stats.CompletedStages == stats.TotalStages {
			stats.CoverageStatus = "COMPLETE"
		}
	}
	if data, err := os.ReadFile(filepath.Join(workDir, ".rfuf", "coverage_report.json")); err == nil {
		var report struct {
			Status string `json:"status"`
		}
		if json.Unmarshal(data, &report) == nil && report.Status != "" {
			stats.CoverageStatus = report.Status
		}
	}
	return stats
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

// getRecentFindings emits up-to-3 high-signal finding flags. Order is
// severity-first: RCE/SQLi/Takeovers are red (Critical/High); Secrets/XSS
// are yellow (Medium). Showing the worst first means the operator's eye
// lands on the most important signal.
func getRecentFindings(stats Stats) []string {
	var res []string
	if stats.Takeovers > 0 {
		res = append(res, "\033[1;31m[!] Subdomain Takeover Found!\033[0m")
	}
	if stats.RCE > 0 {
		res = append(res, "\033[1;31m[!] RCE Vulnerability Found!\033[0m")
	}
	if stats.SQLi > 0 {
		res = append(res, "\033[1;31m[!] SQL Injection Found!\033[0m")
	}
	if stats.Secrets > 0 {
		res = append(res, "\033[1;33m[!] Secrets Exposed!\033[0m")
	}
	if stats.XSS > 0 {
		res = append(res, "\033[1;33m[!] XSS Found!\033[0m")
	}
	if len(res) > 3 {
		res = res[:3]
	}
	if len(res) == 0 {
		res = []string{"Scanning in progress... No critical findings yet."}
	}
	for len(res) < 3 {
		res = append(res, "")
	}
	return res
}
