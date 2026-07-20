package executor

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Duration time.Duration
}

func RunCommand(cmdStr string, workDir string, logFile *os.File) (*Result, error) {
	start := time.Now()

	cmd := exec.Command("bash", "-c", cmdStr)
	cmd.Dir = workDir

	// Log the command
	header := fmt.Sprintf("\n--- [%s] COMMAND: %s ---\n", time.Now().Format(time.RFC3339), cmdStr)
	logFile.WriteString(header)

	// Capture output
	stdoutPipe, _ := cmd.StdoutPipe()
	stderrPipe, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	stdout, _ := io.ReadAll(stdoutPipe)
	stderr, _ := io.ReadAll(stderrPipe)

	err := cmd.Wait()
	duration := time.Since(start)

	exitCode := 0
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			exitCode = -1
		}
	}

	// Write to log
	logFile.Write(stdout)
	logFile.Write(stderr)
	footer := fmt.Sprintf("\n--- [%s] EXIT CODE: %d DURATION: %v ---\n", time.Now().Format(time.RFC3339), exitCode, duration)
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
