package executor

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// logThrottleRate controls how many lines of child-process output we let
// through to the user's terminal. Full output always goes to the log file;
// the terminal stream is throttled so a noisy tool (sqlmap, ffuf, nuclei)
// can't drown the live dashboard. Per the rfuf-tui-dashboard memory
// (single-render-thread + alt-screen + log-throttling), every 25th line is
// a good default — enough signal to know the scan is alive, never enough
// to scroll past the dashboard.
const logThrottleRate = 25

// throttledLineCounter tracks how many lines have been emitted to the
// terminal so far across all child processes in a single pipeline run.
// Using a package-level atomic keeps the throttle global rather than
// per-command; otherwise sqlmap (run alone) would get its first 25 lines
// unmolested, but sqlmap-after-katana would start at 0 again and flood.
var throttledLineCounter uint64

// LineCallback, when set, is invoked for every Nth line of child-process
// output. The pipeline wires this into the TUI's log panel so the live
// terminal sees throttled progress messages while the alt-screen holds the
// dashboard above them. When nil, child output goes only to the log file.
var LineCallback func(line string)

// AuthEnv holds authentication values that should be injected into every
// shell command's environment. Populated from the `-auth-cookie` and
// `-auth-bearer` CLI flags. Empty map means unauthenticated scan.
//
// The keys are env-var names; values are the raw strings to set. Shell
// stage commands reference these via ${RFUF_AUTH_COOKIE}, ${RFUF_AUTH_HEADER}
// and translate them into per-tool flags (httpx -H, nuclei -H, sqlmap
// --cookie/--headers, etc).
//
// Why env vars instead of string substitution into commands: avoids quoting
// nightmares when the cookie contains characters like ';' or '&' that bash
// would otherwise interpret. Each tool reads RFUF_AUTH_* directly.
var AuthEnv = map[string]string{}

// OOBURL is the interactsh callback URL allocated at pipeline boot.
// Empty string means no OOB is wired. Stage commands substitute this
// into blind SSRF/RCE/XSS payloads via ${RFUF_OOB_URL}.
//
// OOBToken is the interactsh auth token (optional, depends on server).
var (
	OOBURL   string
	OOBToken string
)

// Result holds the captured stdout/stderr and exit info for a single
// completed step. The pipeline normally uses ExitCode (and Duration for
// logging); Stdout/Stderr are populated for callers that want to parse
// the raw output, even though the current pipeline does not.
type Result struct {
	Stdout    string
	Stderr    string
	ExitCode  int
	Duration  time.Duration
	TimedOut  bool
	ToolExits []ToolExit
}

// ToolExit records scanner subprocess statuses independently of the shell
// script's final status. This detects a scanner failure even if a legacy
// stage script continues and eventually exits zero.
type ToolExit struct {
	Tool     string
	ExitCode int
}

var trackedTools = []string{
	"subfinder", "assetfinder", "amass", "dnsx", "subzy", "nuclei", "httpx",
	"katana", "trufflehog", "gf", "Gxss", "dalfox", "gau", "waybackurls",
	"ffuf", "naabu", "wafw00f", "arjun", "ghauri", "interactsh-client",
	"sqlmap", "curl", "timeout",
}

// RunCommand executes a shell command, stopping its entire process group when
// the pipeline is cancelled or the step reaches its deadline.
//
// Output handling:
//   - Every byte of stdout/stderr is captured into Result (no truncation).
//   - Every byte is also written to logFile (unthrottled).
//   - Every Nth line is forwarded to LineCallback (if any) so the TUI log
//     panel shows progress without scrolling the dashboard off-screen.
//     N = logThrottleRate.
//
// The full stdout/stderr buffers are returned in Result so callers can
// parse them (the step-type "grep" path uses exit code, but Result is
// available if a future stage needs the raw text).
func RunCommand(parent context.Context, cmdStr string, workDir string, logFile *os.File, timeout time.Duration) (*Result, error) {
	start := time.Now()
	shimDir, toolStatusPath, err := makeToolStatusShims()
	if err != nil {
		return nil, fmt.Errorf("prepare scanner status tracking: %w", err)
	}
	defer os.RemoveAll(shimDir)

	ctx := parent
	cancel := func() {}
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(parent, timeout)
	}
	defer cancel()

	cmd := exec.CommandContext(ctx, "bash", "-c", cmdStr)
	cmd.Dir = workDir

	// Inject rfuf-managed env vars (RFUF_AUTH_*, RFUF_OOB_*) into the
	// child process's environment. Stage commands reference these to
	// thread auth headers and OOB callback URLs through per-tool flags.
	// We append to os.Environ() rather than replacing it so PATH, HOME,
	// and the rest of the user's shell environment still flow through.
	cmd.Env = append(os.Environ(), rfufEnv()...)
	if shimDir != "" {
		cmd.Env = append(cmd.Env, "PATH="+shimDir+string(os.PathListSeparator)+os.Getenv("PATH"))
		cmd.Env = append(cmd.Env, "RFUF_TOOL_STATUS_FILE="+toolStatusPath)
	}

	// Ensure child processes are killed when the parent is killed.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// Send SIGTERM first so commands can flush partial output and logs;
	// the process-group killer escalates to SIGKILL after a grace period.
	// Timeout classification does not depend on the shell's exit status.
	cmd.WaitDelay = 10 * time.Second
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			return cmd.Process.Signal(syscall.SIGTERM)
		}
		return nil
	}

	// Log the command start.
	header := fmt.Sprintf("\n--- [%s] COMMAND START: %s ---\n", time.Now().Format(time.RFC3339), cmdStr)
	logFile.WriteString(header)

	// Capture stdout / stderr in buffers (for Result) and tee through to
	// logFile + LineCallback via the throttled scanner. We use io.Pipe
	// pairs so child writes never block on our scanner lag; the scanners
	// drain the pipes into bytes.Buffer for Result while also forwarding
	// every line to the log file. The throttling applies only to the
	// terminal-facing callback, never to the log file.
	var stdoutBuf, stderrBuf bytes.Buffer
	stdoutR, stdoutW := io.Pipe()
	stderrR, stderrW := io.Pipe()

	logWriter := io.MultiWriter(logFile)

	stdoutDone := make(chan struct{})
	go func() {
		defer close(stdoutDone)
		scanAndForward(stdoutR, logWriter, &stdoutBuf)
	}()
	stderrDone := make(chan struct{})
	go func() {
		defer close(stderrDone)
		scanAndForward(stderrR, logWriter, &stderrBuf)
	}()

	cmd.Stdout = stdoutW
	cmd.Stderr = stderrW

	if err := cmd.Start(); err != nil {
		stdoutW.Close()
		stderrW.Close()
		<-stdoutDone
		<-stderrDone
		return nil, err
	}

	// CommandContext only terminates the shell it starts. Most RFUF stages
	// launch children (and often pipelines), so terminate the shell's
	// process group as well. Without this, a child can keep the stage
	// alive forever.
	done := make(chan struct{})
	go func(pid int) {
		select {
		case <-ctx.Done():
			_ = syscall.Kill(-pid, syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				_ = syscall.Kill(-pid, syscall.SIGKILL)
			}
		case <-done:
		}
	}(cmd.Process.Pid)

	// Wait for command completion or context cancellation. Closing the
	// write ends tells the scanners to drain remaining bytes, then they
	// exit; we wait for both before assembling Result so the buffers are
	// complete.
	waitErr := cmd.Wait()
	stdoutW.Close()
	stderrW.Close()
	<-stdoutDone
	<-stderrDone
	duration := time.Since(start)
	close(done)

	exitCode := 0
	if waitErr != nil {
		if exitError, ok := waitErr.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			exitCode = -1
		}
	}

	footer := fmt.Sprintf("\n--- [%s] COMMAND END: EXIT %d DURATION %v ---\n", time.Now().Format(time.RFC3339), exitCode, duration)
	logFile.WriteString(footer)

	// Preserve timeout status even when a shell wrapper swallowed a child
	// error. Keep the shell's actual exit code for diagnostics; the
	// scheduler must treat TimedOut as incomplete.
	if ctx.Err() != nil {
		if parent.Err() != nil {
			return nil, fmt.Errorf("command interrupted")
		}
		return &Result{
			Stdout:    stdoutBuf.String(),
			Stderr:    stderrBuf.String(),
			ExitCode:  exitCode,
			Duration:  duration,
			TimedOut:  true,
			ToolExits: readToolExits(toolStatusPath),
		}, nil
	}

	return &Result{
		Stdout:    stdoutBuf.String(),
		Stderr:    stderrBuf.String(),
		ExitCode:  exitCode,
		Duration:  duration,
		ToolExits: readToolExits(toolStatusPath),
	}, nil
}

func makeToolStatusShims() (string, string, error) {
	shimDir, err := os.MkdirTemp("", "rfuf-tool-status-")
	if err != nil {
		return "", "", err
	}
	statusPath := filepath.Join(shimDir, "tool-exits.tsv")
	for _, tool := range trackedTools {
		realPath, err := exec.LookPath(tool)
		if err != nil {
			continue
		}
		shim := "#!/bin/sh\n" +
			"real=" + shellQuote(realPath) + "\n" +
			"\"$real\" \"$@\"\n" +
			"rfuf_status=$?\n" +
			"printf '%s\\t%s\\n' " + shellQuote(tool) + " \"$rfuf_status\" >> \"$RFUF_TOOL_STATUS_FILE\"\n" +
			"exit \"$rfuf_status\"\n"
		if err := os.WriteFile(filepath.Join(shimDir, tool), []byte(shim), 0700); err != nil {
			os.RemoveAll(shimDir)
			return "", "", err
		}
	}
	return shimDir, statusPath, nil
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func readToolExits(path string) []ToolExit {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var exits []ToolExit
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != 2 {
			continue
		}
		code, err := strconv.Atoi(fields[1])
		if err == nil {
			exits = append(exits, ToolExit{Tool: fields[0], ExitCode: code})
		}
	}
	return exits
}

func ToolExitError(exits []ToolExit) string {
	var failures []string
	for _, exit := range exits {
		if exit.ExitCode != 0 && exit.ExitCode != 124 && exit.ExitCode != 137 && exit.ExitCode != 143 {
			failures = append(failures, fmt.Sprintf("%s=%d", exit.Tool, exit.ExitCode))
		}
	}
	if len(failures) == 0 {
		return ""
	}
	sortStrings(failures)
	return "scanner_exit: " + strings.Join(failures, ",")
}

func ToolTimedOut(exits []ToolExit) bool {
	for _, exit := range exits {
		if exit.ExitCode == 124 || exit.ExitCode == 137 || exit.ExitCode == 143 {
			return true
		}
	}
	return false
}

// scanAndForward reads one line at a time from r, writes it to logWriter
// (always), appends it to buf (so the caller can return full output in
// Result), and forwards every Nth line to LineCallback (if set) for the
// TUI log panel.
func scanAndForward(r io.Reader, logWriter io.Writer, buf *bytes.Buffer) {
	scanner := bufio.NewScanner(r)
	// Default 64KB buffer; grow to 4MB for the rare multi-MB line
	// (sqlmap traces can produce them).
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := redactSecrets(scanner.Text())
		fmt.Fprintln(logWriter, line)
		buf.WriteString(line)
		buf.WriteByte('\n')
		if LineCallback != nil {
			count := atomic.AddUint64(&throttledLineCounter, 1)
			if count%logThrottleRate == 0 {
				LineCallback(line)
			}
		}
	}
}

func redactSecrets(text string) string {
	secrets := make([]string, 0, len(AuthEnv)+2)
	for key, value := range AuthEnv {
		if strings.Contains(strings.ToLower(key), "auth") && len(value) >= 4 {
			secrets = append(secrets, value)
		}
	}
	for _, value := range []string{OOBToken} {
		if len(value) >= 4 {
			secrets = append(secrets, value)
		}
	}
	sortStrings(secrets)
	for i, j := 0, len(secrets)-1; i < j; i, j = i+1, j-1 {
		secrets[i], secrets[j] = secrets[j], secrets[i]
	}
	for _, secret := range secrets {
		text = strings.ReplaceAll(text, secret, "[REDACTED]")
	}
	return text
}

func GetLogFile(workDir string) (*os.File, error) {
	logDir := filepath.Join(workDir, ".rfuf")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, err
	}
	return os.OpenFile(filepath.Join(logDir, "rfuf.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
}

// ResetLogThrottle zeroes the global line counter. Call between pipeline
// runs so a resumed scan doesn't inherit counters from the previous run.
func ResetLogThrottle() {
	atomic.StoreUint64(&throttledLineCounter, 0)
}

// rfufEnv returns the rfuf-managed env vars as KEY=VALUE strings ready to
// pass to exec.Cmd.Env. Always includes RFUF_OOB_URL and RFUF_OOB_TOKEN
// (empty strings when not set, so shell `${RFUF_OOB_URL:+...}` expansions
// safely evaluate to empty). Auth vars are only present when set.
func rfufEnv() []string {
	env := []string{
		"RFUF_OOB_URL=" + OOBURL,
		"RFUF_OOB_TOKEN=" + OOBToken,
	}
	// Stable ordering for predictable test logs.
	keys := []string{}
	for k := range AuthEnv {
		keys = append(keys, k)
	}
	sortStrings(keys)
	for _, k := range keys {
		env = append(env, k+"="+AuthEnv[k])
	}
	return env
}

// sortStrings is a tiny local sort.Strings wrapper kept inline to avoid an
// extra import at the top of this file (sort is in the stdlib but pulling
// it just for this is heavy). For <=10 keys it's fine.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
