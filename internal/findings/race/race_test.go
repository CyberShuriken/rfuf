package race

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRunProducesManualOnlyCandidates(t *testing.T) {
	dir := t.TempDir()
	input := "https://example.test/api/coupon/redeem\nhttps://example.test/api/health\nhttps://example.test/api/coupon/redeem\n"
	if err := os.WriteFile(filepath.Join(dir, "all_urls.txt"), []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Run(dir); err != nil {
		t.Fatal(err)
	}
	candidates, err := os.ReadFile(filepath.Join(dir, "race_candidates.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(candidates); got != "https://example.test/api/coupon/redeem\thint=coupon-redemption double-spend\n" {
		t.Fatalf("unexpected candidates: %q", got)
	}
	results, err := os.ReadFile(filepath.Join(dir, "race_results.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("manual-only stage produced active results: %q", results)
	}
	var status struct {
		ActiveProbes   bool   `json:"active_probes"`
		Validation     string `json:"validation"`
		CandidateCount int    `json:"candidate_count"`
	}
	data, err := os.ReadFile(filepath.Join(dir, "race_scan_status.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &status); err != nil {
		t.Fatal(err)
	}
	if status.ActiveProbes || status.Validation != "manual_only" || status.CandidateCount != 1 {
		t.Fatalf("unexpected status: %+v", status)
	}
}
