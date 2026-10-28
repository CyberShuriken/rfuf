package evidence

import (
	"os"
	"path/filepath"
	"testing"
)

// An empty directory stage (sqlmap_results with only an "empty" manifest) must
// produce no evidence rows; a directory with a real result file must.
func TestBuildIndexSkipsEmptyManifestDir(t *testing.T) {
	work := t.TempDir()
	dir := filepath.Join(work, "sqlmap_results")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	// The bookkeeping manifest the pipeline writes into every directory output.
	if err := os.WriteFile(filepath.Join(dir, ".rfuf-manifest.json"),
		[]byte(`{"stage_id":"sqlmap_scan","content_status":"empty","file_count":0}`), 0644); err != nil {
		t.Fatal(err)
	}

	records, err := BuildIndex(work)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range records {
		if r.Category == "sqli" {
			t.Fatalf("emitted a sqli evidence row from an empty sqlmap_results: %+v", r)
		}
	}

	// Now add a real result file alongside the manifest; it should be indexed.
	if err := os.WriteFile(filepath.Join(dir, "target_1.txt"),
		[]byte("sqlmap identified the following injection point: https://a.example.com/x?id=1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// content_status now non-empty so the dir is no longer skipped.
	if err := os.WriteFile(filepath.Join(dir, ".rfuf-manifest.json"),
		[]byte(`{"stage_id":"sqlmap_scan","content_status":"nonempty","file_count":1}`), 0644); err != nil {
		t.Fatal(err)
	}
	records, err = BuildIndex(work)
	if err != nil {
		t.Fatal(err)
	}
	gotSQLi := false
	for _, r := range records {
		if r.Category == "sqli" {
			gotSQLi = true
		}
		if filepath.Base(r.EvidenceRef) == ".rfuf-manifest.json" {
			t.Errorf("manifest dotfile was indexed as evidence: %+v", r)
		}
	}
	if !gotSQLi {
		t.Error("expected a sqli evidence row from the real result file")
	}
}
