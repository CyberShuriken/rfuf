package coverage

import (
	"os"
	"path/filepath"
	"strings"
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

// Regression: shell commands routinely use `>&2` for stderr redirection and
// chain statements with `;`. The redirect-extraction regex used to treat
// `>&2` as an output redirect to a file named `&2` (with stray punctuation)
// and bled trailing `;` into filenames, so the amass_enum command — which
// uses both — was misreported as a failed stage despite exit 0. The parser
// must ignore fd-redirect forms and trim shell punctuation.
func TestExtractArtifactPathsIgnoresFdRedirectAndShellPunctuation(t *testing.T) {
	command := `if ! amass enum -passive -norecursive -timeout 30 -d admin.wickr.com -o amass_raw.txt; then echo '[!] Amass enumeration failed; continuing with other sources' >&2; fi; [ -f amass_raw.txt ] || touch amass_raw.txt`
	outputs := ExtractOutputPaths(command)
	for _, p := range outputs {
		if strings.ContainsAny(p, ";&|<>") {
			t.Fatalf("output path %q contains shell punctuation: %v", p, outputs)
		}
	}
	// amass_raw.txt must still be captured (either via -o flag or via the
	// `> amass_raw.txt` redirect in the if-branch).
	found := false
	for _, p := range outputs {
		if p == "amass_raw.txt" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected amass_raw.txt in outputs, got %v", outputs)
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
