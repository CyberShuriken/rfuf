package executor

import (
	"context"
	"os"
	"path/filepath"
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
	res, err := RunCommand(context.Background(), "printf 'partial\\n'; sleep 30; :", t.TempDir(), logFile, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("RunCommand: %v", err)
	}
	if res == nil || !res.TimedOut {
		t.Fatalf("expected timeout status to survive a trailing success command, got %+v", res)
	}
	if res.Stdout == "" || !strings.Contains(res.Stdout, "partial") {
		t.Fatalf("partial output was not preserved on timeout: %+v", res)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("timed out command took too long to stop: %s", elapsed)
	}
}

func TestRunCommandTracksScannerFailureMaskedByShell(t *testing.T) {
	bin := t.TempDir()
	fake := filepath.Join(bin, "nuclei")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\necho fake scanner stderr >&2\nexit 23\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	logFile, err := os.CreateTemp(t.TempDir(), "rfuf.log")
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()

	res, err := RunCommand(context.Background(), "nuclei -l targets.txt || :", t.TempDir(), logFile, time.Second)
	if err != nil {
		t.Fatalf("RunCommand: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("test shell should demonstrate masked failure, got exit %d", res.ExitCode)
	}
	if len(res.ToolExits) != 1 || res.ToolExits[0] != (ToolExit{Tool: "nuclei", ExitCode: 23}) {
		t.Fatalf("scanner failure was not independently recorded: %+v", res.ToolExits)
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
	if !strings.Contains(res.Stdout, "[REDACTED]|https://example.oast.fun") || strings.Contains(res.Stdout, "session=abc123") {
		t.Fatalf("auth secret was not redacted from command output: %q", res.Stdout)
	}
	if err := logFile.Sync(); err != nil {
		t.Fatal(err)
	}
	logged, err := os.ReadFile(logFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(logged), "session=abc123") {
		t.Fatalf("auth secret leaked into persisted command log: %s", logged)
	}
}

func TestFakeScannerStatusMatrix(t *testing.T) {
	for _, tool := range trackedTools {
		t.Run(tool, func(t *testing.T) {
			bin := t.TempDir()
			fake := filepath.Join(bin, tool)
			if err := os.WriteFile(fake, []byte("#!/bin/sh\ncase \"$RFUF_FIXTURE_MODE\" in\n  empty|no_input) exit 0 ;;\n  fail) echo partial-fixture; echo fake-diagnostic >&2; exit 17 ;;\n  timeout) sleep 30 ;;\n  *) echo scanner-output; exit 0 ;;\nesac\n"), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			for _, tc := range []struct {
				mode       string
				wantCode   int
				wantOutput string
				timedOut   bool
			}{
				{mode: "success", wantCode: 0, wantOutput: "scanner-output"},
				{mode: "empty", wantCode: 0},
				{mode: "no_input", wantCode: 0},
				{mode: "fail", wantCode: 17, wantOutput: "partial-fixture"},
				{mode: "timeout", timedOut: true},
			} {
				t.Run(tc.mode, func(t *testing.T) {
					t.Setenv("RFUF_FIXTURE_MODE", tc.mode)
					logFile, err := os.CreateTemp(t.TempDir(), "rfuf.log")
					if err != nil {
						t.Fatal(err)
					}
					defer logFile.Close()
					command := tool + " fixture-input || :"
					timeout := time.Second
					if tc.mode == "no_input" {
						command = tool + " || :"
					}
					if tc.timedOut {
						timeout = 50 * time.Millisecond
					}
					res, err := RunCommand(context.Background(), command, t.TempDir(), logFile, timeout)
					if err != nil {
						t.Fatal(err)
					}
					if res.TimedOut != tc.timedOut {
						t.Fatalf("timeout state=%t want %t", res.TimedOut, tc.timedOut)
					}
					found := tc.timedOut
					for _, exit := range res.ToolExits {
						if exit.Tool == tool && exit.ExitCode == tc.wantCode {
							found = true
						}
					}
					if !found {
						t.Fatalf("missing %s exit code %d in %+v", tool, tc.wantCode, res.ToolExits)
					}
					if tc.wantOutput != "" && !strings.Contains(res.Stdout, tc.wantOutput) {
						t.Fatalf("partial/success output missing: %q", res.Stdout)
					}
					if tc.mode == "fail" && !strings.Contains(res.Stderr, "fake-diagnostic") {
						t.Fatalf("stderr diagnostics lost: %q", res.Stderr)
					}
				})
			}
		})
	}
}
