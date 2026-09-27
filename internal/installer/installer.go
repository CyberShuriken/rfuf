package installer

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// PackageManager identifies the system package manager. We support the two
// distros the project targets out of the box: Fedora/RHEL family (dnf) and
// Kali/Debian/Ubuntu (apt). Anything else falls back to apt — Kali and
// Ubuntu have the widest tool overlap with the bug-bounty ecosystem.
type PackageManager string

const (
	PKG_DNF          PackageManager = "dnf"
	PKG_APT          PackageManager = "apt"
	GFPatternsCommit                = "f686f06ae647726578920084c894100d702496cc"
	SecListsCommit                  = "c5a05259b61cc60dee828ad1bf92c288c7e97ea0"
)

type Tool struct {
	Name           string
	InstallCommand string
	CheckBinary    string
}

var optionalTools = map[string]bool{
	"subfinder": true, "assetfinder": true, "amass": true, "subzy": true,
	"trufflehog": true, "Gxss": true, "dalfox": true, "gau": true,
	"waybackurls": true, "ffuf": true, "naabu": true, "wafw00f": true,
	"arjun": true, "ghauri": true, "interactsh-client": true,
}

var lockedVersions = map[string]string{
	"subfinder": "v2.6.6", "assetfinder": "v0.1.1", "amass": "v4.2.0",
	"dnsx": "v1.2.1", "subzy": "v1.2.0", "nuclei": "v3.3.10",
	"httpx": "v1.6.10", "katana": "v1.1.3", "trufflehog": "v3.97.9",
	"gf": "v0.0.0-20200618134122-dcd4c361f9f5", "Gxss": "v0.0.0-20240804155857-8ee938bf4ead",
	"dalfox": "v2.9.3", "gau": "v2.2.4", "waybackurls": "v0.1.0", "ffuf": "v2.1.0",
	"naabu": "v2.1.9", "wafw00f": "2.4.2", "arjun": "2.2.7",
	"ghauri": "1.4.3", "interactsh-client": "v1.1.9",
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
		{"subfinder", "GOTOOLCHAIN=local go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.6", "subfinder"},
		{"assetfinder", "GOTOOLCHAIN=local go install github.com/tomnomnom/assetfinder@v0.1.1", "assetfinder"},
		{"amass", "GOTOOLCHAIN=local go install -v github.com/owasp-amass/amass/v4/cmd/amass@v4.2.0", "amass"},
		// DNS resolution + takeover checks
		{"dnsx", "GOTOOLCHAIN=local go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.1", "dnsx"},
		{"subzy", "GOTOOLCHAIN=local go install -v github.com/PentestPad/subzy@v1.2.0", "subzy"},
		// Generic scanner
		{"nuclei", "GOTOOLCHAIN=local go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.3.10", "nuclei"},
		// HTTP probing + crawling
		{"httpx", "GOTOOLCHAIN=local go install -v github.com/projectdiscovery/httpx/cmd/httpx@v1.6.10", "httpx"},
		{"katana", "GOTOOLCHAIN=local go install github.com/projectdiscovery/katana/cmd/katana@v1.1.3", "katana"},
		// Secret scanning
		{"trufflehog", fmt.Sprintf("curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/v3.97.9/scripts/install.sh | sh -s -- -b %s v3.97.9", goBin), "trufflehog"},
		// GF patterns + helpers
		{"gf", "GOTOOLCHAIN=local go install github.com/tomnomnom/gf@v0.0.0-20200618134122-dcd4c361f9f5", "gf"},
		{"Gxss", "GOTOOLCHAIN=local go install github.com/KathanP19/Gxss@v0.0.0-20240804155857-8ee938bf4ead", "Gxss"},
		{"dalfox", "GOTOOLCHAIN=local go install github.com/hahwul/dalfox/v2@v2.9.3", "dalfox"},
		// Historical URL mining
		{"gau", "GOTOOLCHAIN=local go install github.com/lc/gau/v2/cmd/gau@v2.2.4", "gau"},
		{"waybackurls", "GOTOOLCHAIN=local go install github.com/tomnomnom/waybackurls@v0.1.0", "waybackurls"},
		// Fuzzing; URL dedup has a built-in sort fallback and needs no tool.
		{"ffuf", "GOTOOLCHAIN=local go install github.com/ffuf/ffuf/v2@v2.1.0", "ffuf"},
		// Port scanning + WAF detection + hidden params per bb-methodology.
		// naabu is Go-installed; wafw00f, arjun, and ghauri are all
		// Python-based in 2026 (Go module paths were deprecated) so we
		// install via pipx or pip3 with --user. The stages that depend
		// on these tools gracefully no-op when the binary is missing, so
		// a pip install failure never blocks the pipeline.
		{"naabu", "GOTOOLCHAIN=local go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.1.9", "naabu"},
		{"wafw00f", "pipx install 'wafw00f==2.4.2' || pip3 install --break-system-packages 'wafw00f==2.4.2' || pip3 install --user 'wafw00f==2.4.2'", "wafw00f"},
		{"arjun", "pipx install 'arjun==2.2.7' || pip3 install --break-system-packages 'arjun==2.2.7' || pip3 install --user 'arjun==2.2.7'", "arjun"},
		{"ghauri", "pipx install 'ghauri @ git+https://github.com/r0oth3x49/ghauri.git@1.4.3' || pip3 install --break-system-packages 'ghauri @ git+https://github.com/r0oth3x49/ghauri.git@1.4.3'", "ghauri"},
		// interactsh-client: OOB callback server used by the new SSRF/RCE/XSS
		// stages to catch blind results that don't trip templates. Allocates
		// a unique *.oast.fun (or self-hosted) URL at pipeline boot that
		// becomes the substitute target for blind payloads.
		{"interactsh-client", "GOTOOLCHAIN=local go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@v1.1.9", "interactsh-client"},
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
// before the pipeline started doing real work.
func VerifyToolsPresent() error {
	// Loop over every tool defined in GetRequiredTools and look up the
	// CheckBinary on PATH. We deliberately don't try to repair anything
	// here — if something is missing, the user should run the install
	// path once without -resume.
	fmt.Printf("%-20s %-10s %-20s %-32s %s\n", "TOOL", "REQUIRED", "STATUS", "VERSION", "PATH")
	missingRequired := []string{}
	for _, t := range GetRequiredTools("") {
		resolved, err := exec.LookPath(t.CheckBinary)
		required := !optionalTools[t.Name]
		if err != nil {
			state := "missing_required"
			if optionalTools[t.Name] {
				state = "skipped_optional"
			} else {
				missingRequired = append(missingRequired, t.Name)
			}
			fmt.Printf("%-20s %-10t %-20s %-32s %s\n", t.Name, required, state, "—", "—")
			continue
		}
		version := installedVersion(resolved)
		if locked := pinnedVersion(t); locked != "unlocked" {
			version += " (pin " + locked + ")"
		}
		fmt.Printf("%-20s %-10t %-20s %-32s %s\n", t.Name, required, "installed", version, resolved)
	}
	for _, tool := range []struct {
		name     string
		required bool
	}{
		{name: "bash", required: true}, {name: "curl", required: true},
		{name: "jq", required: true}, {name: "timeout", required: true},
		{name: "awk", required: true}, {name: "grep", required: true},
		{name: "sort", required: true}, {name: "sed", required: true},
		{name: "xargs", required: true}, {name: "git", required: true},
		{name: "sqlmap", required: false},
	} {
		resolved, err := exec.LookPath(tool.name)
		if err != nil {
			status := "skipped_optional"
			if tool.required {
				status = "missing_required"
				missingRequired = append(missingRequired, tool.name)
			}
			fmt.Printf("%-20s %-10t %-20s %-32s %s\n", tool.name, tool.required, status, "—", "—")
			continue
		}
		fmt.Printf("%-20s %-10t %-20s %-32s %s\n", tool.name, tool.required, "installed", installedVersion(resolved), resolved)
	}
	home, _ := os.UserHomeDir()
	wordlist := ""
	for _, candidate := range []string{"/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt", "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt", filepath.Join(home, "SecLists/Discovery/Web-Content/raft-medium-directories.txt")} {
		if _, err := os.Stat(candidate); err == nil {
			wordlist = candidate
			break
		}
	}
	if wordlist == "" {
		fmt.Printf("%-20s %-10t %-20s %-32s %s\n", "seclists", false, "skipped_optional", "—", "—")
	} else {
		fmt.Printf("%-20s %-10t %-20s %-32s %s\n", "seclists", false, "installed", "operator/package", wordlist)
	}
	if len(missingRequired) > 0 {
		return fmt.Errorf("missing required tools (run `rfuf -d <domain>` once WITHOUT -resume to install): %s", strings.Join(missingRequired, ", "))
	}
	return nil
}

func installedVersion(path string) string {
	for _, args := range [][]string{{"--version"}, {"-version"}, {"version"}} {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		output, err := exec.CommandContext(ctx, path, args...).CombinedOutput()
		cancel()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(output), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if len(line) > 120 {
				line = line[:120]
			}
			return line
		}
	}
	return "unreported"
}

func pinnedVersion(tool Tool) string {
	if version := lockedVersions[tool.Name]; version != "" {
		return version
	}
	return "unlocked"
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
	versionOutput, err := exec.Command("go", "env", "GOVERSION").Output()
	if err != nil {
		return fmt.Errorf("cannot determine local Go version: %w", err)
	}
	if err := validateGoVersion(strings.TrimSpace(string(versionOutput))); err != nil {
		return err
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
	for _, logical := range []string{"build", "git", "jq", "sqlmap", "seclists"} {
		names := distroPkgs[logical]
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
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		cmd := exec.CommandContext(ctx, "bash", "-c", installCmd)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {

			// Don't fail the whole pipeline — fall through and let the
			// per-tool check below produce a clearer error if the binary
			// is genuinely missing after the package install attempt.
			fmt.Printf("[!] %s install returned %v (will check PATH next)\n", logical, err)
		}
		cancel()
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
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		cmd := exec.CommandContext(ctx, "bash", "-c", t.InstallCommand)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			cancel()
			if optionalTools[t.Name] {
				fmt.Printf("[!] Optional tool %s %s could not be installed: %v\n", t.Name, pinnedVersion(t), err)
				continue
			}
			return fmt.Errorf("failed to install %s: %v", t.Name, err)
		}
		cancel()
		// Nuclei needs templates before its first scan can do anything
		// useful. Updating templates on every install is wasteful, but
		// doing it once at first-install time is the right trade-off.
		if t.Name == "nuclei" {
			fmt.Println("[*] Updating nuclei templates (first-time setup)...")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			updateCmd := exec.CommandContext(ctx, "nuclei", "-update-templates")
			updateCmd.Stdout = os.Stdout
			updateCmd.Stderr = os.Stderr
			if err := updateCmd.Run(); err != nil {
				cancel()
				return fmt.Errorf("failed to install nuclei templates: %w", err)
			}
			cancel()
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
		if _, err := os.Stat(patternPath); err != nil {
			fmt.Printf("[DEBUG] Stat error for %s: %v\n", patternPath, err)
			if os.IsNotExist(err) {
				return fmt.Errorf("required GF pattern %s.json missing in %s — clone https://github.com/1ndianl33t/Gf-Patterns into %s", p, filepath.Join(home, ".gf"), filepath.Join(home, ".gf"))
			}
			return fmt.Errorf("error accessing GF pattern %s.json: %v", p, err)
		}
	}

	return VerifyToolsPresent()
}

func validateGoVersion(output string) error {
	version := regexp.MustCompile(`^go([0-9]+)\.([0-9]+)(?:\.([0-9]+))?`).FindStringSubmatch(strings.TrimSpace(output))
	if len(version) == 0 {
		return fmt.Errorf("cannot parse local Go version %q", strings.TrimSpace(output))
	}
	major, _ := strconv.Atoi(version[1])
	minor, _ := strconv.Atoi(version[2])
	patch := 0
	if version[3] != "" {
		patch, _ = strconv.Atoi(version[3])
	}
	if major < 1 || (major == 1 && (minor < 22 || (minor == 22 && patch < 2))) {
		return fmt.Errorf("Go 1.22.2 or newer is required (found %s); dependency installs use GOTOOLCHAIN=local and will not fetch another toolchain", strings.TrimSpace(output))
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
	if _, err := os.Stat(gfDir); err == nil {
		// Operator-managed pattern directories are never mutated by bootstrap.
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect GF pattern directory: %w", err)
	}
	fmt.Printf("[*] Installing GF patterns at commit %s...\n", GFPatternsCommit)
	return cloneAtCommit("https://github.com/1ndianl33t/Gf-Patterns.git", GFPatternsCommit, gfDir, 5*time.Minute)
}

func cloneAtCommit(repository, commit, destination string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := os.MkdirAll(destination, 0755); err != nil {
		return fmt.Errorf("create checkout directory: %w", err)
	}
	commands := [][]string{
		{"init", "--quiet"},
		{"remote", "add", "origin", repository},
		{"-c", "protocol.version=2", "fetch", "--depth=1", "origin", commit},
		{"checkout", "--quiet", "--detach", "FETCH_HEAD"},
	}
	for _, args := range commands {
		cmd := exec.CommandContext(ctx, "git", append([]string{"-C", destination}, args...)...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("git %s for pinned dependency %s: %w", strings.Join(args, " "), repository, err)
		}
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
		if err := cloneAtCommit("https://github.com/danielmiessler/SecLists.git", SecListsCommit, cloneDst, 15*time.Minute); err != nil {
			return "", fmt.Errorf("failed to clone pinned SecLists: %w", err)
		}
	default:
		fmt.Println("[*] Installing seclists...")
		// Best-effort: most Kali/Debian systems ship seclists; Ubuntu
		// sometimes doesn't. We don't fail the whole pipeline if this
		// fails — the user can still run the rest of the stages.
		aptCtx, aptCancel := context.WithTimeout(context.Background(), 5*time.Minute)
		if err := exec.CommandContext(aptCtx, "sudo", "apt", "update").Run(); err != nil {
			fmt.Printf("[!] apt index refresh failed (%v); trying the package once, then the pinned Git fallback\n", err)
		}
		aptCancel()
		installCtx, installCancel := context.WithTimeout(context.Background(), 10*time.Minute)
		if err := exec.CommandContext(installCtx, "sudo", "apt", "install", "-y", "seclists").Run(); err != nil {
			installCancel()
			fmt.Printf("[!] apt install seclists failed (%v) — falling back to git clone\n", err)
			cloneDst := filepath.Join(home, "SecLists")
			if err := cloneAtCommit("https://github.com/danielmiessler/SecLists.git", SecListsCommit, cloneDst, 15*time.Minute); err != nil {
				return "", fmt.Errorf("failed to install or clone pinned SecLists: %w", err)
			}
		} else {
			installCancel()
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
