package executor

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRunCommandStopsProcessGroupAtDeadline(t *testing.T) {
	logFile, err := os.CreateTemp(t.TempDir(), "rfuf.log")
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()

	started := time.Now()
	res, err := RunCommand(context.Background(), "sleep 30 & wait", t.TempDir(), logFile, 50*time.Millisecond)
	// Per the soft-cancel semantics: a per-step deadline is treated as a
	// success (exit code 0) so the orchestrator's `; true` wrapper intent
	// is honored. The previous test expected a "timed out" error string,
	// which was the old hard-failure contract; this now matches the
	// runner's intent of letting partial output count as a checkpoint.
	if err != nil {
		t.Fatalf("expected soft-success on timeout, got %v", err)
	}
	if res == nil || res.ExitCode != 0 {
		t.Fatalf("expected ExitCode 0 on timeout, got %+v", res)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("timed out command took too long to stop: %s", elapsed)
	}
}

func TestRunCommandInterruptedReturnsError(t *testing.T) {
	// User-initiated cancellation (parent ctx cancelled) must still
	// surface as an error so Ctrl-C aborts cleanly.
	logFile, err := os.CreateTemp(t.TempDir(), "rfuf.log")
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	_, err = RunCommand(ctx, "sleep 30", t.TempDir(), logFile, 0)
	if err == nil || !strings.Contains(err.Error(), "interrupted") {
		t.Fatalf("expected interrupted error, got %v", err)
	}
}

func TestRunCommandInjectsRfufEnv(t *testing.T) {
	// Stage commands reference RFUF_AUTH_COOKIE / RFUF_OOB_URL. Confirm
	// they're visible inside the child shell.
	logFile, err := os.CreateTemp(t.TempDir(), "rfuf.log")
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()

	prevAuth := AuthEnv
	prevOOB := OOBURL
	defer func() {
		AuthEnv = prevAuth
		OOBURL = prevOOB
	}()
	AuthEnv = map[string]string{"RFUF_AUTH_COOKIE": "session=abc123"}
	OOBURL = "https://example.oast.fun"

	res, err := RunCommand(context.Background(),
		"echo \"$RFUF_AUTH_COOKIE|$RFUF_OOB_URL\"",
		t.TempDir(), logFile, 5*time.Second)
	if err != nil {
		t.Fatalf("RunCommand: %v", err)
	}
	if !strings.Contains(res.Stdout, "session=abc123|https://example.oast.fun") {
		t.Fatalf("env injection failed; got stdout=%q", res.Stdout)
	}
}
