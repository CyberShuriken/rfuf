package executor

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Duration time.Duration
}

// RunCommand executes a shell command with signal handling and logging
func RunCommand(cmdStr string, workDir string, logFile *os.File) (*Result, error) {
	start := time.Now()

	// Create a context that is cancelled on interrupt signal
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cmd := exec.CommandContext(ctx, "bash", "-c", cmdStr)
	cmd.Dir = workDir
	
	// Ensure child processes are killed when the parent is killed
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// Log the command start
	header := fmt.Sprintf("\n--- [%s] COMMAND START: %s ---\n", time.Now().Format(time.RFC3339), cmdStr)
	logFile.WriteString(header)

	// Capture output
	stdoutPipe, _ := cmd.StdoutPipe()
	stderrPipe, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	// Read output in goroutines to prevent blocking
	stdoutChan := make(chan []byte)
	stderrChan := make(chan []byte)
	go func() {
		out, _ := io.ReadAll(stdoutPipe)
		stdoutChan <- out
	}()
	go func() {
		errOut, _ := io.ReadAll(stderrPipe)
		stderrChan <- errOut
	}()

	// Wait for command completion or context cancellation
	err := cmd.Wait()
	duration := time.Since(start)

	// Kill the process group if context was cancelled (Ctrl+C)
	if ctx.Err() != nil {
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		return nil, fmt.Errorf("command interrupted by user")
	}

	stdout := <-stdoutChan
	stderr := <-stderrChan

	exitCode := 0
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			exitCode = -1
		}
	}

	// Write results to log
	logFile.Write(stdout)
	logFile.Write(stderr)
	footer := fmt.Sprintf("\n--- [%s] COMMAND END: EXIT %d DURATION %v ---\n", time.Now().Format(time.RFC3339), exitCode, duration)
	logFile.WriteString(footer)

	return &Result{
		Stdout:   string(stdout),
		Stderr:   string(stderr),
		ExitCode: exitCode,
		Duration: duration,
	}, nil
}

func GetLogFile(workDir string) (*os.File, error) {
	logDir := filepath.Join(workDir, ".rfuf")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, err
	}
	return os.OpenFile(filepath.Join(logDir, "rfuf.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
}
