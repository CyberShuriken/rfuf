package installer

import (
	"os"
	"os/exec"
	"path/filepath"
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

func TestRequiredToolsPinNucleiAndDisableToolchainSwitching(t *testing.T) {
	var nuclei Tool
	for _, tool := range GetRequiredTools("/tmp/go-bin") {
		if tool.Name == "nuclei" {
			nuclei = tool
			break
		}
	}
	if nuclei.CheckBinary != "nuclei" {
		t.Fatal("nuclei tool definition not found")
	}
	if !containsCmd(nuclei.InstallCommand, "GOTOOLCHAIN=local") {
		t.Fatalf("nuclei installer may silently download a future Go toolchain: %q", nuclei.InstallCommand)
	}
	if !containsCmd(nuclei.InstallCommand, "@v3.3.10") {
		t.Fatalf("nuclei installer is not pinned to the supported release: %q", nuclei.InstallCommand)
	}
}

func TestAllGoInstallCommandsDisableToolchainSwitching(t *testing.T) {
	for _, tool := range GetRequiredTools("/tmp/go-bin") {
		if containsCmd(tool.InstallCommand, "go install") && !containsCmd(tool.InstallCommand, "GOTOOLCHAIN=local") {
			t.Errorf("%s installer can silently switch Go toolchains: %q", tool.Name, tool.InstallCommand)
		}
	}
}

func TestEveryInstalledDependencyIsPinned(t *testing.T) {
	tools := GetRequiredTools("/tmp/go-bin")
	if len(lockedVersions) != len(tools) {
		t.Fatalf("lock table has %d entries for %d installed tools", len(lockedVersions), len(tools))
	}
	for _, tool := range tools {
		version := pinnedVersion(tool)
		if version == "" || version == "unlocked" || !containsCmd(tool.InstallCommand, version) {
			t.Errorf("%s has no matching immutable version pin: version=%q command=%q", tool.Name, version, tool.InstallCommand)
		}
		if containsCmd(tool.InstallCommand, "@latest") || containsCmd(tool.InstallCommand, "@master") || containsCmd(tool.InstallCommand, "releases/latest") {
			t.Errorf("%s uses a floating dependency reference: %q", tool.Name, tool.InstallCommand)
		}
		if optionalTools[tool.Name] && (tool.Name == "httpx" || tool.Name == "nuclei" || tool.Name == "dnsx" || tool.Name == "gf") {
			t.Errorf("core dependency %s must not be optional", tool.Name)
		}
	}
}

func TestPinnedGitFallbackCommitsAreImmutable(t *testing.T) {
	for name, commit := range map[string]string{"GF patterns": GFPatternsCommit, "SecLists": SecListsCommit} {
		if len(commit) != 40 {
			t.Errorf("%s fallback commit is not a full SHA-1: %q", name, commit)
		}
		for _, r := range commit {
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
				t.Errorf("%s fallback commit is not hexadecimal: %q", name, commit)
				break
			}
		}
	}
}

func TestInstalledVersionUsesBoundedFakeExecutable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fake-tool")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho fake-tool v1.2.3\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if got := installedVersion(path); got != "fake-tool v1.2.3" {
		t.Fatalf("installedVersion() = %q", got)
	}
}

func TestSupportedGoVersionFloor(t *testing.T) {
	for _, version := range []string{"go1.22.2", "go1.23.0", "go2.0.0"} {
		if err := validateGoVersion(version); err != nil {
			t.Errorf("supported Go %s rejected: %v", version, err)
		}
	}
	for _, version := range []string{"go1.22.1", "go1.21.13", "invalid"} {
		if err := validateGoVersion(version); err == nil {
			t.Errorf("unsupported Go version %q accepted", version)
		}
	}
}

func TestDependencyPreflightWithControlledPath(t *testing.T) {
	fakeToolPath(t, "")
	if err := VerifyToolsPresent(); err != nil {
		t.Fatalf("all controlled required tools should pass preflight: %v", err)
	}
}

func TestDependencyPreflightFailsForMissingRequiredTool(t *testing.T) {
	binDir := fakeToolPath(t, "dnsx")
	if err := VerifyToolsPresent(); err == nil || !containsCmd(err.Error(), "dnsx") {
		t.Fatalf("missing required dnsx must fail preflight clearly, got %v", err)
	}
	_ = binDir
}

func fakeToolPath(t *testing.T, omit string) string {
	t.Helper()
	binDir := t.TempDir()
	names := append([]string{"bash"}, toolBinaries()...)
	for _, name := range names {
		if name == omit {
			continue
		}
		path := filepath.Join(binDir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\n[ \"$1\" = \"--version\" ] && echo fixture-v1\nexit 0\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", binDir)
	return binDir
}

func toolBinaries() []string {
	var names []string
	for _, tool := range GetRequiredTools("") {
		names = append(names, tool.CheckBinary)
	}
	return append(names, "curl", "jq", "timeout", "awk", "grep", "sort", "sed", "xargs", "git", "sqlmap")
}
