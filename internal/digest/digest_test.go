package digest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestBuildAggregatesFindingsAndDeltas(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "credentials_found.txt", "https://x/.env\n")
	writeFile(t, dir, "xss_vulnerabilities.txt", "https://x/?q=<svg>\nhttps://x/?s=<svg>\n")
	writeFile(t, dir, "hostheader_findings.txt", "https://x/ host-injection\n")
	writeFile(t, dir, "new_subdomains.txt", "beta.x.com\n")
	writeFile(t, dir, "new_js_assets.txt", "")

	d, err := Build(dir, "x.com")
	if err != nil {
		t.Fatal(err)
	}
	if d.Domain != "x.com" {
		t.Fatalf("domain=%q", d.Domain)
	}
	if d.TotalFindings != 4 { // 1 cred + 2 xss + 1 hostheader
		t.Fatalf("total findings=%d want 4", d.TotalFindings)
	}
	if len(d.NewSubdomains) != 1 || d.NewSubdomains[0] != "beta.x.com" {
		t.Fatalf("new subdomains=%v", d.NewSubdomains)
	}
	// Most-severe category must sort first (CRITICAL credentials).
	if d.Findings[0].Severity != "CRITICAL" || d.Findings[0].Name != "exposed_credentials" {
		t.Fatalf("first finding=%+v want CRITICAL exposed_credentials", d.Findings[0])
	}
	// hostheader_findings.txt must be picked up by the generic glob.
	var sawHostHeader bool
	for _, c := range d.Findings {
		if c.Name == "hostheader" {
			sawHostHeader = true
		}
	}
	if !sawHostHeader {
		t.Fatal("generic *_findings.txt glob missed hostheader_findings.txt")
	}

	// findings.json must be written and parse back.
	raw, err := os.ReadFile(filepath.Join(dir, "findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var round Digest
	if err := json.Unmarshal(raw, &round); err != nil {
		t.Fatalf("findings.json invalid: %v", err)
	}
	if round.TotalFindings != 4 {
		t.Fatalf("round-trip total=%d", round.TotalFindings)
	}
}

func TestBuildEmptyWorkspaceIsSafe(t *testing.T) {
	dir := t.TempDir()
	d, err := Build(dir, "empty.com")
	if err != nil {
		t.Fatalf("empty workspace should not error: %v", err)
	}
	if d.TotalFindings != 0 || len(d.Findings) != 0 {
		t.Fatalf("expected no findings, got %+v", d)
	}
	if _, err := os.Stat(filepath.Join(dir, "findings.json")); err != nil {
		t.Fatalf("findings.json not written: %v", err)
	}
}
