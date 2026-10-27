package digest

import (
	"os"
	"path/filepath"
	"testing"
)

// A nuclei [info] line must not be counted as a submittable finding even though
// it lands in a file whose hand-assigned severity is CRITICAL, and generically
// globbed *_findings.txt must be informational-only.
func TestBuildHonorsNucleiSeverityAndTiers(t *testing.T) {
	work := t.TempDir()
	// credentials_found.txt is a confirmed coreSource (hand-assigned CRITICAL),
	// but nuclei tags each line with its real severity.
	write(t, work, "credentials_found.txt",
		"[adobe-embed] [http] [info] https://a.example.com/embed\n"+
			"[git-config] [http] [high] https://a.example.com/.git/config\n")
	// A generically-globbed finder file — heuristic, informational tier.
	write(t, work, "foo_findings.txt", "https://a.example.com/x\nhttps://a.example.com/y\n")

	d, err := Build(work, "example.com")
	if err != nil {
		t.Fatal(err)
	}

	creds := findCategory(d, "exposed_credentials")
	if creds == nil {
		t.Fatal("exposed_credentials category missing")
	}
	if creds.Severity != "HIGH" {
		t.Errorf("category severity = %q, want HIGH (max real line severity, not CRITICAL)", creds.Severity)
	}
	if creds.Submittable != 1 {
		t.Errorf("submittable = %d, want 1 (the [high] line only; [info] excluded)", creds.Submittable)
	}

	foo := findCategory(d, "foo")
	if foo == nil || foo.Tier != tierInformational {
		t.Fatalf("foo category tier = %v, want informational", foo)
	}
	if foo.Submittable != 0 {
		t.Errorf("informational submittable = %d, want 0", foo.Submittable)
	}

	if d.SubmittableFindings != 1 {
		t.Errorf("SubmittableFindings = %d, want 1", d.SubmittableFindings)
	}
	if d.InformationalFindings != 2 {
		t.Errorf("InformationalFindings = %d, want 2", d.InformationalFindings)
	}
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func findCategory(d Digest, name string) *Category {
	for i := range d.Findings {
		if d.Findings[i].Name == name {
			return &d.Findings[i]
		}
	}
	return nil
}
