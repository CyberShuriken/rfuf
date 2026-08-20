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
	Stdout   string
	Stderr   string
	ExitCode int
	Duration time.Duration
	TimedOut bool
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

	// Ensure child processes are killed when the parent is killed.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// Soft cancellation: when the per-step deadline fires, send SIGTERM
	// to the outer bash (not SIGKILL) and let it run the trailing
	// `; true` fallback. Default exec.CommandContext cancels with
	// cmd.Process.Kill() which is SIGKILL — that kills bash before
	// `; touch xss_vulnerabilities.txt ; true` ever runs, the wrapper
	// never produces exit code 0, and the timeout surfaces as a hard
	// failure. SIGTERM + WaitDelay lets bash exit cleanly with status 0
	// so the orchestrator's `; true` wrapper does its job. The
	// process-group SIGKILL below is still the hard backstop if bash
	// ignores SIGTERM (e.g. wedged dalfox browser pool).
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

	// Context timeout handling. Two cases to disambiguate:
	//
	//   (a) The shell `timeout --foreground N` killed the process *and* the
	//       command returned non-zero. The orchestrator wraps the call in
	//       `... ; true` so exitCode is 0 anyway — record this as success.
	//
	//   (b) The executor's `context.WithTimeout` SIGTERMed the process group
	//       (race with shell `timeout`; same wall-clock cap). The cmd.Wait()
	//       returned an *exec.ExitError with non-zero code (signal exit).
	//       exitCode is -1 in that branch.
	//
	// Treat any per-step deadline as a soft success regardless of exit
	// code: the orchestrator's `; true` was *meant* to make the timeout
	// path exit 0, and honoring that intent — even when SIGTERM raced
	// with the wrapper and bash exited via signal — keeps the pipeline
	// moving and preserves partial output. Only signal user-initiated
	// cancellation as an error so Ctrl-C still aborts cleanly.
	if ctx.Err() != nil {
		if parent.Err() != nil {
			return nil, fmt.Errorf("command interrupted")
		}
		return &Result{
			Stdout:   stdoutBuf.String(),
			Stderr:   stderrBuf.String(),
			ExitCode: 0,
			Duration: duration,
			TimedOut: true,
		}, nil
	}

	return &Result{
		Stdout:   stdoutBuf.String(),
		Stderr:   stderrBuf.String(),
		ExitCode: exitCode,
		Duration: duration,
	}, nil
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
		line := scanner.Text()
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
