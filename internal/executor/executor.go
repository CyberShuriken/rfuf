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

// Result holds the captured stdout/stderr and exit info for a single
// completed step. The pipeline normally uses ExitCode (and Duration for
// logging); Stdout/Stderr are populated for callers that want to parse
// the raw output, even though the current pipeline does not.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Duration time.Duration
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

	// Ensure child processes are killed when the parent is killed.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

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

	if ctx.Err() != nil {
		if parent.Err() != nil {
			return nil, fmt.Errorf("command interrupted")
		}
		return nil, fmt.Errorf("command timed out after %s", timeout)
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
