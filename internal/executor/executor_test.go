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
	_, err = RunCommand(context.Background(), "sleep 30 & wait", t.TempDir(), logFile, 50*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected timeout error, got %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("timed out command took too long to stop: %s", elapsed)
	}
}
