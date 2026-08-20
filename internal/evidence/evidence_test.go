package evidence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildIndexDoesNotCopySecretValues(t *testing.T) {
	dir := t.TempDir()
	secret := "AKIA1234567890ABCDEF"
	content := "https://example.com/api token=" + secret + "\n"
	if err := os.WriteFile(filepath.Join(dir, "potential_secrets.txt"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	records, err := BuildIndex(dir)
	if err != nil || len(records) != 1 {
		t.Fatalf("records=%+v err=%v", records, err)
	}
	if records[0].Target != "https://example.com/api" || records[0].ValidationState != "candidate" {
		t.Fatalf("unexpected record: %+v", records[0])
	}
	if err := WriteIndex(dir, records); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "evidence.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) {
		t.Fatal("evidence index copied a secret value")
	}
}
