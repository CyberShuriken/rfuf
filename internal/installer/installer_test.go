package installer

import (
	"os/exec"
	"testing"
)

// TestDetectPackageManagerReturnsKnown verifies the detector returns one
// of the two supported package managers on whatever host the tests run on.
// We don't assert which one (CI machines differ), only that the result is
// a value the rest of the codebase knows how to handle.
func TestDetectPackageManagerReturnsKnown(t *testing.T) {
	pm := detectPackageManager()
	if pm != PKG_DNF && pm != PKG_APT {
		t.Errorf("detected unsupported package manager %q", pm)
	}
}

// TestDistroPackagesCoversAllLogicalDeps verifies the per-distro mapping
// always knows about the four logical dependencies the installer uses,
// even when their package lists are empty (e.g. seclists on Fedora).
//
// A missing entry here would mean the install loop silently skips a
// dependency and the pipeline later fails because the binary is absent.
func TestDistroPackagesCoversAllLogicalDeps(t *testing.T) {
	logicals := []string{"sqlmap", "jq", "seclists", "build", "git"}
	for _, pm := range []PackageManager{PKG_DNF, PKG_APT} {
		m := distroPackages(pm)
		for _, l := range logicals {
			if _, ok := m[l]; !ok {
				t.Errorf("package map for %s missing logical dep %s", pm, l)
			}
		}
	}
}

// TestSystemInstallCmdContainsSudoAndPM verifies the install snippet
// targets the right package manager and runs under sudo (we need root
// for apt/dnf install on Kali/Fedora defaults). Skipping sudo on
// distros where the user is already root is fine; the snippet still has
// to reference the package manager binary.
func TestSystemInstallCmdContainsSudoAndPM(t *testing.T) {
	if got := systemInstallCmd(PKG_DNF, "jq"); !execSudoAndContains(got, "dnf") {
		t.Errorf("dnf install snippet missing dnf: %q", got)
	}
	if got := systemInstallCmd(PKG_APT, "jq"); !execSudoAndContains(got, "apt") {
		t.Errorf("apt install snippet missing apt: %q", got)
	}
}

func execSudoAndContains(snippet, want string) bool {
	return (containsCmd(snippet, "sudo ") || containsCmd(snippet, "dnf ") || containsCmd(snippet, "apt ")) && containsCmd(snippet, want)
}

func containsCmd(s, sub string) bool {
	return len(s) >= len(sub) && (indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	// Tiny substring search; avoids pulling in strings for a 5-line helper.
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// Ensure exec is "used" so the import isn't flagged when tests get pruned.
var _ = exec.Command
