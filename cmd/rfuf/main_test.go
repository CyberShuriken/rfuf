package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CyberShuriken/rfuf/internal/executor"
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
