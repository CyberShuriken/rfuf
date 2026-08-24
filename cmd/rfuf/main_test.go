package main

import (
	"net/http"
	"net/http/httptest"
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
