package diffsnap

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func loadReport(t *testing.T, dir string) report {
	t.Helper()
	var rep report
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(dir, "diff_report.json"))), &rep); err != nil {
		t.Fatal(err)
	}
	return rep
}

func artifact(rep report, label string) artifactDiff {
	for _, a := range rep.Artifacts {
		if a.Label == label {
			return a
		}
	}
	return artifactDiff{}
}

func TestFirstRunEstablishesBaselineWithNoDeltas(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "live_subs.txt", "api.example.com\nwww.example.com\n")
	write(t, dir, "js_assets.txt", "https://www.example.com/app.js\n")

	if err := Run(dir); err != nil {
		t.Fatal(err)
	}
	rep := loadReport(t, dir)
	if !rep.BaselineEstablished {
		t.Fatal("first run should flag baseline_established")
	}
	if got := strings.TrimSpace(readFile(t, filepath.Join(dir, "new_subdomains.txt"))); got != "" {
		t.Fatalf("first run must not flag existing subdomains as new, got %q", got)
	}
	// Baseline snapshot must exist for the next run to diff against.
	if _, err := os.Stat(filepath.Join(dir, ".rfuf", "history", "latest", "live_subs.txt")); err != nil {
		t.Fatalf("baseline not promoted: %v", err)
	}
}

func TestSecondRunReportsOnlyNewEntries(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "live_subs.txt", "api.example.com\nwww.example.com\n")
	write(t, dir, "js_assets.txt", "https://www.example.com/app.js\n")
	if err := Run(dir); err != nil {
		t.Fatal(err)
	}

	// Second run: one new subdomain, one removed; one new JS asset.
	write(t, dir, "live_subs.txt", "api.example.com\nbeta.example.com\n")
	write(t, dir, "js_assets.txt", "https://www.example.com/app.js\nhttps://beta.example.com/new.js\n")
	if err := Run(dir); err != nil {
		t.Fatal(err)
	}

	rep := loadReport(t, dir)
	if rep.BaselineEstablished {
		t.Fatal("second run should not re-establish baseline")
	}
	if rep.PreviousTimestamp == "" {
		t.Fatal("second run should record the previous snapshot timestamp")
	}

	subs := artifact(rep, "subdomains")
	if len(subs.New) != 1 || subs.New[0] != "beta.example.com" {
		t.Fatalf("subdomain new=%v want [beta.example.com]", subs.New)
	}
	if len(subs.Removed) != 1 || subs.Removed[0] != "www.example.com" {
		t.Fatalf("subdomain removed=%v want [www.example.com]", subs.Removed)
	}
	if got := strings.TrimSpace(readFile(t, filepath.Join(dir, "new_subdomains.txt"))); got != "beta.example.com" {
		t.Fatalf("new_subdomains.txt=%q want beta.example.com", got)
	}

	js := artifact(rep, "js_assets")
	if len(js.New) != 1 || js.New[0] != "https://beta.example.com/new.js" {
		t.Fatalf("js new=%v want [https://beta.example.com/new.js]", js.New)
	}
}

func TestNoChangeProducesEmptyDeltas(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "live_subs.txt", "api.example.com\n")
	write(t, dir, "js_assets.txt", "")
	if err := Run(dir); err != nil {
		t.Fatal(err)
	}
	if err := Run(dir); err != nil {
		t.Fatal(err)
	}
	rep := loadReport(t, dir)
	if artifact(rep, "subdomains").NewCount != 0 {
		t.Fatal("unchanged inventory must report zero new subdomains")
	}
	if got := strings.TrimSpace(readFile(t, filepath.Join(dir, "new_subdomains.txt"))); got != "" {
		t.Fatalf("new_subdomains.txt should be empty, got %q", got)
	}
}

func TestMissingInventoryIsSafe(t *testing.T) {
	dir := t.TempDir()
	// No live_subs.txt or js_assets.txt at all — must not error.
	if err := Run(dir); err != nil {
		t.Fatalf("missing inventories should be tolerated: %v", err)
	}
	rep := loadReport(t, dir)
	if !rep.BaselineEstablished {
		t.Fatal("first run with no inventory still establishes baseline")
	}
}
