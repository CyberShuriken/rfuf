package coverage

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExtractArtifactPaths(t *testing.T) {
	command := `httpx -l alive.txt -o all_urls_200.txt; nuclei -l nuclei_targets.txt -o nuclei_findings.txt`
	inputs := ExtractInputPaths(command)
	outputs := ExtractOutputPaths(command)
	if len(inputs) == 0 || len(outputs) == 0 {
		t.Fatalf("expected input/output paths, got inputs=%v outputs=%v", inputs, outputs)
	}
}

func TestMeasureArtifactsAndEvaluate(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "input.txt"), []byte("a\nb\n"), 0644); err != nil {
		t.Fatal(err)
	}
	metrics := MeasureArtifacts(dir, []string{"input.txt", "missing.txt"})
	if metrics[0].Lines != 2 || !metrics[0].Exists || metrics[1].Exists {
		t.Fatalf("unexpected metrics: %+v", metrics)
	}
	now := time.Now()
	report := Evaluate("example.com", now, now, []StageRecord{
		{StageID: "ok", Required: true, Status: StatusCompleted},
		{StageID: "empty", Required: true, Status: StatusCompletedEmpty},
		{StageID: "timeout", Required: true, Status: StatusTimedOut},
	})
	if report.Status != "INCOMPLETE" || report.CompletedStages != 1 || report.EmptyStages != 1 || report.TimedOutStages != 1 {
		t.Fatalf("unexpected coverage report: %+v", report)
	}
}

func TestWriteAndLoadStageRecords(t *testing.T) {
	dir := t.TempDir()
	record := StageRecord{StageID: "stage-a", Required: true, Status: StatusCompleted, ExitCode: 0}
	if err := WriteStageRecord(dir, record); err != nil {
		t.Fatal(err)
	}
	got, err := LoadStageRecords(dir)
	if err != nil || len(got) != 1 || got[0].StageID != record.StageID {
		t.Fatalf("records=%+v err=%v", got, err)
	}
	if err := WriteReport(dir, Evaluate("example.com", time.Now(), time.Now(), got)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".rfuf", "coverage_report.json")); err != nil {
		t.Fatal(err)
	}
}
