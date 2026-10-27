package iohelp

import (
	"os"
	"testing"
)

func TestInScope(t *testing.T) {
	// Exact scope: only the root itself is in scope.
	os.Setenv("RFUF_SCOPE_INPUT", "saytechnologies.com")
	defer os.Unsetenv("RFUF_SCOPE_INPUT")

	cases := map[string]bool{
		"saytechnologies.com":     true,
		"app.saytechnologies.com": false, // exact mode excludes subdomains
		"robinhood.com":           false, // the reported out-of-scope leak
		"evil.com":                false,
	}
	for host, want := range cases {
		if got := InScope(host); got != want {
			t.Errorf("exact InScope(%q) = %v, want %v", host, got, want)
		}
	}

	// Wildcard scope: root and its subdomains are in scope; others are not.
	os.Setenv("RFUF_SCOPE_INPUT", "*.saytechnologies.com")
	wild := map[string]bool{
		"app.saytechnologies.com": true,
		"saytechnologies.com":     true,
		"robinhood.com":           false,
	}
	for host, want := range wild {
		if got := InScope(host); got != want {
			t.Errorf("wildcard InScope(%q) = %v, want %v", host, got, want)
		}
	}

	// No scope configured: fail open so a misconfigured run doesn't silently
	// drop every host-bearing finding.
	os.Unsetenv("RFUF_SCOPE_INPUT")
	if !InScope("anything.com") {
		t.Error("InScope should fail open when no scope is configured")
	}
}
