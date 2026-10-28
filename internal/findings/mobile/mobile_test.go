package mobile

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeAPK(t *testing.T, path string, entries map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for name, content := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(content))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestMobileExtractsInScopeEndpointsAndSecrets(t *testing.T) {
	os.Setenv("RFUF_SCOPE_INPUT", "*.example.com")
	defer os.Unsetenv("RFUF_SCOPE_INPUT")

	work := t.TempDir()
	art := filepath.Join(work, "mobile_artifacts")
	if err := os.MkdirAll(art, 0755); err != nil {
		t.Fatal(err)
	}
	writeAPK(t, filepath.Join(art, "app.apk"), map[string]string{
		"classes.dex": `endpoints: https://api.example.com/v1/users https://evil-sdk.com/track aws=AKIAABCDEFGHIJKLMNOP`,
		"res/x.xml":   `<string>https://auth.example.com/login</string>`,
	})

	if err := Run(work); err != nil {
		t.Fatal(err)
	}

	eps := readFile(t, filepath.Join(work, "mobile_endpoints.txt"))
	if !strings.Contains(eps, "api.example.com/v1/users") || !strings.Contains(eps, "auth.example.com/login") {
		t.Errorf("in-scope endpoints missing: %q", eps)
	}
	if strings.Contains(eps, "evil-sdk.com") {
		t.Errorf("out-of-scope host leaked into endpoints: %q", eps)
	}
	finds := readFile(t, filepath.Join(work, "mobile_findings.txt"))
	if !strings.Contains(finds, "aws_access_key") {
		t.Errorf("embedded AWS key not reported: %q", finds)
	}
	if !strings.Contains(finds, "evil-sdk.com") {
		t.Errorf("out-of-scope url should be noted as external: %q", finds)
	}
}

func TestMobileNoArtifactsIsCleanNoop(t *testing.T) {
	work := t.TempDir()
	if err := Run(work); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"mobile_endpoints.txt", "mobile_findings.txt"} {
		if _, err := os.Stat(filepath.Join(work, f)); err != nil {
			t.Errorf("declared output %s not created on empty run: %v", f, err)
		}
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
