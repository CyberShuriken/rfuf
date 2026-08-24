package iohelp

import (
	"os"
	"testing"
)

func TestBuildAuthHeadersIncludesProgramHeaders(t *testing.T) {
	previous := map[string]string{
		"RFUF_BUG_BOUNTY_USERNAME": os.Getenv("RFUF_BUG_BOUNTY_USERNAME"),
		"RFUF_TEST_ACCOUNT_EMAIL":  os.Getenv("RFUF_TEST_ACCOUNT_EMAIL"),
	}
	defer func() {
		for key, value := range previous {
			if value == "" {
				_ = os.Unsetenv(key)
			} else {
				_ = os.Setenv(key, value)
			}
		}
	}()
	_ = os.Setenv("RFUF_BUG_BOUNTY_USERNAME", "soumo6t9")
	_ = os.Setenv("RFUF_TEST_ACCOUNT_EMAIL", "test@example.com")

	got := BuildAuthHeaders()
	seen := map[string]string{}
	for _, header := range got {
		seen[header.Key] = header.Value
	}
	if seen["X-Bug-Bounty"] != "soumo6t9" {
		t.Fatalf("X-Bug-Bounty = %q", seen["X-Bug-Bounty"])
	}
	if seen["X-HackerOne-Research"] != "soumo6t9" {
		t.Fatalf("X-HackerOne-Research = %q", seen["X-HackerOne-Research"])
	}
	if seen["X-Test-Account-Email"] != "test@example.com" {
		t.Fatalf("X-Test-Account-Email = %q", seen["X-Test-Account-Email"])
	}
}
