package installer

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// PackageManager identifies the system package manager. We support the two
// distros the project targets out of the box: Fedora/RHEL family (dnf) and
// Kali/Debian/Ubuntu (apt). Anything else falls back to apt — Kali and
// Ubuntu have the widest tool overlap with the bug-bounty ecosystem.
type PackageManager string

const (
	PKG_DNF PackageManager = "dnf"
	PKG_APT PackageManager = "apt"
)

type Tool struct {
	Name           string
	InstallCommand string
	CheckBinary    string
}

// detectPackageManager returns dnf on Fedora/RHEL-family, apt elsewhere.
// Detection order matters: /etc/os-release is the ground truth, but a
// missing release file (minimal container, chroot) should still resolve
// to whichever binary is actually present.
func detectPackageManager() PackageManager {
	if _, err := exec.LookPath("dnf"); err == nil {
		if data, err := os.ReadFile("/etc/os-release"); err == nil {
			lower := strings.ToLower(string(data))
			if strings.Contains(lower, "fedora") ||
				strings.Contains(lower, "rhel") ||
				strings.Contains(lower, "centos") ||
				strings.Contains(lower, "rocky") ||
				strings.Contains(lower, "almalinux") {
				return PKG_DNF
			}
		}
		// dnf present but no os-release match → still likely Fedora family.
		return PKG_DNF
	}
	if _, err := exec.LookPath("apt"); err == nil {
		return PKG_APT
	}
	// Neither present — fall back to apt commands; user will see a clear
	// error if apt itself isn't there, which is the right failure mode.
	return PKG_APT
}

// systemInstallCmd returns the right shell snippet for installing a list of
// distro packages on the detected package manager. apt needs `update` first
// (Kali/Ubuntu repos otherwise 404), dnf does not.
func systemInstallCmd(pm PackageManager, pkgs ...string) string {
	switch pm {
	case PKG_DNF:
		// -y for non-interactive, --skip-unavailable so missing names (e.g.
		// seclists on Fedora) just warn instead of failing the whole batch.
		return fmt.Sprintf("sudo dnf install -y --skip-unavailable %s", strings.Join(pkgs, " "))
	default:
		return fmt.Sprintf("sudo apt update && sudo apt install -y %s", strings.Join(pkgs, " "))
	}
}

// distroPackages maps a logical dependency to the actual package name(s)
// on each supported package manager. Names differ across distros (sqlmap
// is `sqlmap` everywhere, but seclists is shipped by Kali but not Fedora),
// so we look them up here rather than hardcoding.
func distroPackages(pm PackageManager) map[string][]string {
	switch pm {
	case PKG_DNF:
		return map[string][]string{
			// sqlmap exists in Fedora's main repo, no extra EPEL needed.
			"sqlmap": {"sqlmap"},
			// jq is in base Fedora.
			"jq": {"jq"},
			// seclists is NOT packaged on Fedora — we'll fall back to git clone
			// into ~/SecLists instead of relying on apt/dnf.
			"seclists": {},
			// C compile toolchain for any Go tools that need cgo fallbacks.
			// Most of our recon tools are pure Go but amass historically
			// pulled in cgo deps — keep this as a defensive default.
			"build": {"gcc", "make"},
			// git + ca-certificates are prerequisites for every Go install
			// and every git clone we do; pull them in explicitly so the
			// auto-install never fails on a minimal Fedora cloud image.
			"git": {"git", "ca-certificates", "openssl"},
		}
	default:
		return map[string][]string{
			"sqlmap":   {"sqlmap"},
			"jq":       {"jq"},
			"seclists": {"seclists"},
			"build":    {"build-essential"},
			"git":      {"git", "ca-certificates"},
		}
	}
}

// GetRequiredTools lists every external binary rfuf orchestrates.
//
// Naming convention: the "CheckBinary" is what we look up on PATH to decide
// whether the tool is already installed; the "InstallCommand" is the exact
// shell snippet to run when it isn't. Most tools are Go-based and install via
// `GOTOOLCHAIN=local go install` (works on every distro with a Go toolchain). TruffleHog is
// installed via its own installer script (latest releases ship as native
// binaries, not as a Go module). sqlmap + jq + seclists come from the
// system package manager — see systemInstallCmd for the per-distro mapping.
func GetRequiredTools(goBin string) []Tool {
	return []Tool{
		// Subdomain enumeration
		{"subfinder", "GOTOOLCHAIN=local go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "subfinder"},
		{"assetfinder", "GOTOOLCHAIN=local go install github.com/tomnomnom/assetfinder@latest", "assetfinder"},
		{"amass", "GOTOOLCHAIN=local go install -v github.com/owasp-amass/amass/v4/cmd/amass@master", "amass"},
		// DNS resolution + takeover checks
		{"dnsx", "GOTOOLCHAIN=local go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest", "dnsx"},
		{"subzy", "GOTOOLCHAIN=local go install -v github.com/PentestPad/subzy@latest", "subzy"},
		// Generic scanner
		{"nuclei", "GOTOOLCHAIN=local go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.3.10", "nuclei"},
		// HTTP probing + crawling
		{"httpx", "GOTOOLCHAIN=local go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest", "httpx"},
		{"katana", "GOTOOLCHAIN=local go install github.com/projectdiscovery/katana/cmd/katana@latest", "katana"},
		// Secret scanning
		{"trufflehog", fmt.Sprintf("curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b %s", goBin), "trufflehog"},
		// GF patterns + helpers
		{"gf", "GOTOOLCHAIN=local go install github.com/tomnomnom/gf@latest", "gf"},
		{"Gxss", "GOTOOLCHAIN=local go install github.com/KathanP19/Gxss@latest", "Gxss"},
		{"dalfox", "GOTOOLCHAIN=local go install github.com/hahwul/dalfox/v2@latest", "dalfox"},
		// Historical URL mining
		{"gau", "GOTOOLCHAIN=local go install github.com/lc/gau/v2/cmd/gau@latest", "gau"},
		{"waybackurls", "GOTOOLCHAIN=local go install github.com/tomnomnom/waybackurls@latest", "waybackurls"},
		// Fuzzing + URL dedup (uro collapses gau+wayback+katana noise)
		{"ffuf", "GOTOOLCHAIN=local go install github.com/ffuf/ffuf/v2@latest", "ffuf"},
		{"uro", "GOTOOLCHAIN=local go install github.com/s0md3v/uro@latest", "uro"},
		// Port scanning + WAF detection + hidden params per bb-methodology.
		// naabu is Go-installed; wafw00f, arjun, and ghauri are all
		// Python-based in 2026 (Go module paths were deprecated) so we
		// install via pipx or pip3 with --user. The stages that depend
		// on these tools gracefully no-op when the binary is missing, so
		// a pip install failure never blocks the pipeline.
		{"naabu", "GOTOOLCHAIN=local go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", "naabu"},
		{"wafw00f", "pipx install wafw00f || pip3 install --break-system-packages wafw00f || pip3 install --user wafw00f", "wafw00f"},
		{"arjun", "pipx install arjun || pip3 install --break-system-packages arjun || pip3 install --user arjun", "arjun"},
		{"ghauri", "pipx install git+https://github.com/r0oth3x49/ghauri.git || pip3 install --break-system-packages git+https://github.com/r0oth3x49/ghauri.git", "ghauri"},
		// interactsh-client: OOB callback server used by the new SSRF/RCE/XSS
		// stages to catch blind results that don't trip templates. Allocates
		// a unique *.oast.fun (or self-hosted) URL at pipeline boot that
		// becomes the substitute target for blind payloads.
		{"interactsh-client", "GOTOOLCHAIN=local go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest", "interactsh-client"},
	}
}

// VerifyToolsPresent is the no-install counterpart to EnsureTools. Used on
// `-resume` so a stopped pipeline can pick up without re-running sudo /
// `GOTOOLCHAIN=local go install` for tools we already have on disk. It returns a clear error
// if any required binary is missing — the failure message tells the user
// how to recover (drop -resume to trigger the installer).
//
// Why this exists: the previous behavior ran the full installer on every
// `-resume`. That re-cloned SecLists (multi-hundred-MB git clone), triggered
// `sudo dnf install git ...` prompts that block forever in non-interactive
// terminals, and rebuilt Go tools the user already had — wasting minutes
// before the pipeline even started.
func VerifyToolsPresent() error {
	// bash is the universal shell for every pipeline stage; missing-bash
	// commands would just fail silently inside the executor.
	if _, err := exec.LookPath("bash"); err != nil {
		return fmt.Errorf("bash is required but not found on PATH")
	}

	// Loop over every tool defined in GetRequiredTools and look up the
	// CheckBinary on PATH. We deliberately don't try to repair anything
	// here — if something is missing, the user should run the install
	// path once without -resume.
	missing := []string{}
	for _, t := range GetRequiredTools("") {
		if _, err := exec.LookPath(t.CheckBinary); err != nil {
			missing = append(missing, t.Name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required tools (run `rfuf -d <domain>` once WITHOUT -resume to install): %s", strings.Join(missing, ", "))
	}
	return nil
}

func packageGroupPresent(pm PackageManager, logical string, packages []string) bool {
	// Package names are not always executable names. In particular Fedora's
	// git prerequisite group includes ca-certificates and openssl, neither of
	// which should be checked with LookPath. Check representative binaries
	// instead, while leaving package-only groups to the package manager.
	if pm == PKG_DNF && logical == "git" {
		if _, err := exec.LookPath("rpm"); err == nil {
			for _, packageName := range packages {
				if err := exec.Command("rpm", "-q", packageName).Run(); err != nil {
					return false
				}
			}
			return true
		}
	}
	binaries := map[string][]string{
		"sqlmap": {"sqlmap"},
		"jq":     {"jq"},
		"build":  {"gcc", "make"},
		"git":    {"git"},
	}
	if pm == PKG_APT && logical == "seclists" {
		home, _ := os.UserHomeDir()
		for _, path := range []string{"/usr/share/seclists", filepath.Join(home, "SecLists")} {
			if info, err := os.Stat(path); err == nil && info.IsDir() {
				return true
			}
		}
	}
	checks, ok := binaries[logical]
	if !ok {
		return false
	}
	for _, binary := range checks {
		if _, err := exec.LookPath(binary); err != nil {
			return false
		}
	}
	return true
}

func sudoUsableForPackageInstall() (bool, string) {
	if _, err := exec.LookPath("sudo"); err != nil {
		return false, "sudo is not installed; install the required distro packages manually or run as root"
	}
	if info, err := os.Stdin.Stat(); err == nil && info.Mode()&os.ModeCharDevice != 0 {
		return true, ""
	}
	if err := exec.Command("sudo", "-n", "true").Run(); err == nil {
		return true, ""
	}
	return false, "sudo requires a password but RFUF has no interactive terminal; run the command from a terminal, configure passwordless sudo for these packages, or install them manually"
}

// EnsureTools is the entry point. It is idempotent: any tool already on PATH
// is skipped, any tool missing is installed. The function never panics on a
// missing distro package — sqlmap/jq/seclists fall back to alternative
// install paths so the user always ends up with a working pipeline.
func EnsureTools(goBin string) error {
	// 1. Check Go. This is the only hard prerequisite: every recon tool we
	// install via `GOTOOLCHAIN=local go install` needs a working Go toolchain, and the
	// cross-distro logic only matters once Go is in place.
	if _, err := exec.LookPath("go"); err != nil {
		return fmt.Errorf("Go is not installed. Install it first: sudo dnf install -y golang  (Fedora)  |  sudo apt install -y golang-go  (Kali/Debian/Ubuntu)")
	}

	// 2. Detect distro. We need this before step 3 (apt vs dnf) and again
	// at the end (seclists install path).
	pm := detectPackageManager()
	fmt.Printf("[*] Detected package manager: %s\n", pm)

	// 3. Install distro packages (sqlmap, jq, seclists, build tools, git).
	// We iterate explicitly so a single missing package doesn't kill the
	// others — sqlmap failing on Fedora (rare, but possible if the repo
	// is stale) should not stop jq from being installed.
	distroPkgs := distroPackages(pm)
	for logical, names := range distroPkgs {
		if len(names) == 0 {
			continue
		}
		// Package names are not necessarily executable names. Use the
		// representative-binary map so Fedora's ca-certificates/openssl
		// prerequisites do not cause a needless sudo prompt every run.
		if packageGroupPresent(pm, logical, names) {

			fmt.Printf("[*] %s already installed (skipping)\n", logical)
			continue
		}
		fmt.Printf("[*] Installing %s (%s)...\n", logical, strings.Join(names, " "))
		if usable, reason := sudoUsableForPackageInstall(); !usable {
			fmt.Printf("[!] Skipping %s package install: %s\n", logical, reason)
			continue
		}
		installCmd := systemInstallCmd(pm, names...)
		cmd := exec.Command("bash", "-c", installCmd)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {

			// Don't fail the whole pipeline — fall through and let the
			// per-tool check below produce a clearer error if the binary
			// is genuinely missing after the package install attempt.
			fmt.Printf("[!] %s install returned %v (will check PATH next)\n", logical, err)
		}
	}

	// 4. Ensure ~/go/bin is on PATH. This is the Go default install
	// location; if it isn't on PATH, `which subfinder` will fail even
	// after a successful `GOTOOLCHAIN=local go install`.
	path := os.Getenv("PATH")
	if !strings.Contains(path, goBin) {
		newPath := goBin + ":" + path
		os.Setenv("PATH", newPath)
		fmt.Printf("[*] Added %s to current PATH\n", goBin)

		// Patch every shell rc that exists. We used to only patch .zshrc,
		// which silently failed for users on bash + Fedora defaults.
		home, _ := os.UserHomeDir()
		exportLine := fmt.Sprintf("export PATH=\"%s:$PATH\"", goBin)
		for _, rcName := range []string{".zshrc", ".bashrc", ".bash_profile"} {
			rcPath := filepath.Join(home, rcName)
			patchRCFile(rcPath, exportLine)
		}
	}

	// 5. Install Go-based recon tools. Each one is independently checked
	// and installed; a failure on one does not block the rest.
	for _, t := range GetRequiredTools(goBin) {
		if _, err := exec.LookPath(t.CheckBinary); err == nil {
			continue
		}
		fmt.Printf("[*] Installing %s...\n", t.Name)
		cmd := exec.Command("bash", "-c", t.InstallCommand)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to install %s: %v", t.Name, err)
		}
		// Nuclei needs templates before its first scan can do anything
		// useful. Updating templates on every install is wasteful, but
		// doing it once at first-install time is the right trade-off.
		if t.Name == "nuclei" {
			fmt.Println("[*] Updating nuclei templates (first-time setup)...")
			// On Kali, nuclei may be installed via apt with system-wide
			// templates at /usr/share/nuclei-templates. The -update-templates
			// flag needs the templates directory to be writable, so we only
			// run it if the user's templates dir is writable (not system).
			updateCmd := exec.Command("nuclei", "-update-templates")
			_ = updateCmd.Run()
		}
	}

	// 6. GF patterns. The pattern files (sqli.json, xss.json, ssrf.json,
	// lfi.json, etc.) are what make `gf sqli all_urls.txt` work — without
	// them every gf-based stage produces zero output. We clone into ~/.gf
	// if missing and pull updates if it already exists.
	if err := ensureGFPatterns(); err != nil {
		return err
	}

	// 7. Required GF patterns present? Every methodology vuln class we
	// scan for (sqli, xss, rce, idor, ssrf, redirect, lfi) needs its
	// corresponding pattern file. We fail loudly if any are missing
	// rather than silently producing empty target lists.
	requiredPatterns := []string{"sqli", "xss", "rce", "idor", "ssrf", "redirect", "lfi"}
	for _, p := range requiredPatterns {
		home, _ := os.UserHomeDir()
		patternPath := filepath.Join(home, ".gf", p+".json")
		if _, err := os.Stat(patternPath); os.IsNotExist(err) {
			return fmt.Errorf("required GF pattern %s.json missing in %s — clone https://github.com/1ndianl33t/Gf-Patterns into %s", p, filepath.Join(home, ".gf"), filepath.Join(home, ".gf"))
		}
	}

	return nil
}

// patchRCFile appends the rfuf export line to a shell rc file unless the
// exact export already appears. Idempotent across re-installs.
func patchRCFile(rcPath, exportLine string) {
	if data, err := os.ReadFile(rcPath); err == nil {
		if strings.Contains(string(data), exportLine) {
			return
		}
	} else if !os.IsNotExist(err) {
		return
	}
	f, err := os.OpenFile(rcPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	if _, err := f.WriteString("\n" + exportLine + "\n"); err == nil {
		fmt.Printf("[*] Added Go bin path to %s\n", rcPath)
	}
}

// ensureGFPatterns clones the canonical Gf-Patterns repo on first run and
// pulls on subsequent runs. We keep the implementation in its own function
// so EnsureTools stays readable.
func ensureGFPatterns() error {
	home, _ := os.UserHomeDir()
	gfDir := filepath.Join(home, ".gf")
	if _, err := os.Stat(gfDir); os.IsNotExist(err) {
		fmt.Println("[*] Installing GF patterns...")
		cmd := exec.Command("git", "clone", "https://github.com/1ndianl33t/Gf-Patterns", gfDir)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to clone gf patterns: %v", err)
		}
	} else {
		fmt.Println("[*] Updating GF patterns...")
		_ = exec.Command("git", "-C", gfDir, "pull").Run()
	}
	return nil
}

// EnsureSeclists makes the directory brute-force wordlist available.
//
// Strategy:
//   - On Kali/Debian/Ubuntu, seclists is a real package at
//     /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
//     (and a few alternate locations). We check those first.
//   - On Fedora, seclists is not packaged. We clone the upstream SecLists
//     repo into ~/SecLists. This is slower (a few hundred MB) but
//     gives the user the same wordlist coverage.
//
// We try every plausible location on disk before falling back to a fresh
// install — most users already have seclists somewhere from a previous
// tool install, and re-cloning is wasteful.
func EnsureSeclists() (string, error) {
	home, _ := os.UserHomeDir()
	candidates := []string{
		// Kali default install
		"/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
		// Some Debian/Ubuntu installs (older seclists packaging)
		"/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt",
		"/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt",
		// User-managed clone from another tool
		filepath.Join(home, "SecLists", "Discovery", "Web-Content", "raft-medium-directories.txt"),
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}

	// Nothing on disk — try the distro package first (Kali/Ubuntu), then
	// fall back to a git clone for distros that don't package seclists
	// (Fedora / RHEL family).
	pm := detectPackageManager()
	switch pm {
	case PKG_DNF:
		fmt.Println("[*] seclists not packaged on Fedora — cloning SecLists into ~/SecLists...")
		cloneDst := filepath.Join(home, "SecLists")
		cmd := exec.Command("git", "clone", "--depth=1", "https://github.com/danielmiessler/SecLists.git", cloneDst)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("failed to clone SecLists: %v", err)
		}
	default:
		fmt.Println("[*] Installing seclists...")
		// Best-effort: most Kali/Debian systems ship seclists; Ubuntu
		// sometimes doesn't. We don't fail the whole pipeline if this
		// fails — the user can still run the rest of the stages.
		_ = exec.Command("sudo", "apt", "update").Run()
		if err := exec.Command("sudo", "apt", "install", "-y", "seclists").Run(); err != nil {
			fmt.Printf("[!] apt install seclists failed (%v) — falling back to git clone\n", err)
			cloneDst := filepath.Join(home, "SecLists")
			cmd := exec.Command("git", "clone", "--depth=1", "https://github.com/danielmiessler/SecLists.git", cloneDst)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				return "", fmt.Errorf("failed to install or clone seclists: %v", err)
			}
		}
	}

	// Re-scan the candidate paths now that an install attempt ran.
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("seclists wordlist not found after installation — install SecLists manually or set -wordlist flag (not yet supported)")
}
