package owasp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CyberShuriken/rfuf/internal/coverage"
	"github.com/CyberShuriken/rfuf/internal/evidence"
)

func TestGenerateWritesCoverageAndManualPlan(t *testing.T) {
	workDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(workDir, "idor_surface.txt"), []byte("id\tMEDIUM\thosts=2\tids=3\texample=https://api.example.com/orders?id=1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "manual_business_logic_review.txt"), []byte("https://shop.example.com/coupon?code=TEST\n"), 0600); err != nil {
		t.Fatal(err)
	}
	report := coverage.CoverageReport{Domain: "example.com", Status: "COMPLETE", StartedAt: time.Now(), FinishedAt: time.Now(), TotalStages: 1, CompletedStages: 1}
	records := []coverage.StageRecord{{StageID: "idor_surface_run", Status: coverage.StatusCompleted}, {StageID: "manual_review_queue", Status: coverage.StatusCompleted}}
	evidenceRecords := []evidence.Record{{Category: "idor", SourceStage: "idor_scan", Target: "https://api.example.com/orders?id=1", Severity: "high", Confidence: "candidate", ValidationState: "candidate", EvidenceRef: "idor_vulnerabilities.txt", Line: 1}}
	if err := Generate(workDir, "example.com", report, records, evidenceRecords); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"candidate_index.jsonl", "OWASP_2025_COVERAGE.md", "MANUAL_TEST_PLAN.md"} {
		if _, err := os.Stat(filepath.Join(workDir, name)); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
	plan, err := os.ReadFile(filepath.Join(workDir, "MANUAL_TEST_PLAN.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(plan), "two authorized accounts") {
		t.Error("manual plan does not contain the A01 two-account instruction")
	}
}

func TestRedactLine(t *testing.T) {
	got := redactLine("Authorization=Bearer super-secret-value")
	if strings.Contains(got, "super-secret-value") || !strings.Contains(got, "<redacted>") {
		t.Fatalf("redactLine leaked a secret: %q", got)
	}
}
