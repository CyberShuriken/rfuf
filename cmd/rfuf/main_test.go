package main

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CyberShuriken/rfuf/internal/executor"
	"github.com/CyberShuriken/rfuf/internal/notify"
)

func TestVerifyAuthSessionSendsConfiguredHeaders(t *testing.T) {
	previous := executor.AuthEnv
	defer func() { executor.AuthEnv = previous }()
	executor.AuthEnv = map[string]string{
		"RFUF_AUTH_COOKIE":         "session=test",
		"RFUF_AUTH_HEADER":         "Bearer token",
		"RFUF_BUG_BOUNTY_USERNAME": "researcher",
		"RFUF_TEST_ACCOUNT_EMAIL":  "test@example.com",
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "session=test" || r.Header.Get("Authorization") != "Bearer token" || r.Header.Get("X-Bug-Bounty") != "researcher" || r.Header.Get("X-HackerOne-Research") != "researcher" || r.Header.Get("X-Test-Account-Email") != "test@example.com" {
			http.Error(w, "missing headers", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("AUTHENTICATED"))
	}))
	defer server.Close()

	verified, status, err := verifyAuthSession(server.URL, "AUTHENTICATED")
	if err != nil || !verified || status != http.StatusOK {
		t.Fatalf("verified=%v status=%d err=%v", verified, status, err)
	}
}

func TestAuthHealthMetadataUsesSafeClassAndNeverPersistsSecrets(t *testing.T) {
	dir := t.TempDir()
	secretURL := "https://example.test/check?token=top-secret-value"
	checkErr := errors.New("Get " + secretURL + ": connection refused")
	if err := writeAuthCheckMetadata(dir, true, false, 0, checkErr); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, ".rfuf", "auth_check.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "top-secret-value") || strings.Contains(string(data), secretURL) || strings.Contains(string(data), "connection refused") {
		t.Fatalf("auth metadata persisted raw error or secret: %s", data)
	}
	for _, want := range []string{`"mode": "authenticated_unverified"`, `"error_class": "request_failed"`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("metadata missing %s: %s", want, data)
		}
	}
}

func TestRunTargetStreamWritesCanonicalTargetsAndMetadata(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "input.txt")
	if err := os.WriteFile(in, []byte("HTTPS://API.FIXTURE.TEST:443/path#fragment\nhttps://api.fixture.test/path\nhttps://outside.test/path\nhttps://api.fixture.test/private\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RFUF_SCOPE_INPUT", "*.fixture.test")
	t.Setenv("RFUF_EXCLUDE_URL_REGEX", `/private`)
	args := []string{"-input", in, "-output", filepath.Join(dir, "out.txt"), "-source", "fixture", "-status", filepath.Join(dir, "status.json"), "-provenance", filepath.Join(dir, "provenance.jsonl"), "-max-targets", "10"}
	if err := runTargetStream(args); err != nil {
		t.Fatal(err)
	}
	output, err := os.ReadFile(filepath.Join(dir, "out.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(output) != "https://api.fixture.test/path\n" {
		t.Fatalf("unexpected canonical stream: %q", output)
	}
	status, err := os.ReadFile(filepath.Join(dir, "status.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"duplicate_count": 1`, `"excluded_count": 1`, `"out_of_scope_count": 1`, `"final_count": 1`} {
		if !strings.Contains(string(status), want) {
			t.Errorf("status missing %s: %s", want, status)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "provenance.jsonl")); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyAuthSessionMarkerMismatch(t *testing.T) {
	previous := executor.AuthEnv
	defer func() { executor.AuthEnv = previous }()
	executor.AuthEnv = map[string]string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("PUBLIC"))
	}))
	defer server.Close()

	verified, status, err := verifyAuthSession(server.URL, "AUTHENTICATED")
	if err != nil || verified || status != http.StatusOK {
		t.Fatalf("verified=%v status=%d err=%v", verified, status, err)
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "  ", "x", "y"); got != "x" {
		t.Fatalf("firstNonEmpty=%q want x", got)
	}
	if got := firstNonEmpty("", ""); got != "" {
		t.Fatalf("firstNonEmpty of empties=%q want empty", got)
	}
}

func TestRunMonitorValidatesArgs(t *testing.T) {
	if err := runMonitor([]string{"-interval"}); err == nil {
		t.Fatal("missing -interval value should error")
	}
	if err := runMonitor([]string{"-interval", "nonsense", "-d", "x"}); err == nil {
		t.Fatal("bad -interval duration should error")
	}
	if err := runMonitor([]string{"-interval", "30s", "-d", "x"}); err == nil {
		t.Fatal("sub-minute interval should be rejected")
	}
	if err := runMonitor([]string{"-iterations", "-5", "-d", "x"}); err == nil {
		t.Fatal("negative -iterations should error")
	}
}

func TestRunReportingWritesFindingsAndNotifies(t *testing.T) {
	dir := t.TempDir()
	// Simulate a completed run's artifacts.
	if err := os.WriteFile(filepath.Join(dir, "credentials_found.txt"), []byte("https://x/.env\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "new_subdomains.txt"), []byte("beta.example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}

	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		gotBody = string(data)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	runReporting(dir, "example.com", notify.Config{Webhook: srv.URL, Type: "slack", On: "change"})

	if _, err := os.Stat(filepath.Join(dir, "findings.json")); err != nil {
		t.Fatalf("findings.json not written: %v", err)
	}
	if !strings.Contains(gotBody, "beta.example.com") {
		t.Fatalf("notification did not include new subdomain; body=%q", gotBody)
	}
}
