package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Paths struct {
	NucleiTemplates     string
	NucleiTemplatesRfuf string // Absolute path to the bundled nuclei-templates-rfuf/ overlay
	GfPatterns          string
	WorkDir             string
	GoBin               string
	// SeclistsDirWordlist is the large wordlist (raft-medium). Kept for
	// fallback if the small list isn't found anywhere on disk.
	SeclistsDirWordlist string
	// SeclistsDirWordlistSmall is the curated small wordlist (~4k words).
	// Default for ffuf — fewer false positives and ~7x faster against the
	// same number of hosts. Falls back to SeclistsDirWordlist at use site.
	SeclistsDirWordlistSmall string
	// SeclistsDNSWordlist is a DNS subdomain prefix list (not web-content
	// directories). Used only by subdomain_brute.
	SeclistsDNSWordlist string
	// AssetnoteWordlist is the Assetnote curated wordlist.
	AssetnoteWordlist string
	// UserWordlist is a wordlist override provided via CLI flag.
	UserWordlist string
}

// Settings holds user-configurable defaults loaded from the config file and
// environment. CLI flags take precedence over these at the call site.
// Precedence, high to low: flag > environment variable > config file > the
// built-in default.
type Settings struct {
	// OutputDir is the base directory under which per-domain work
	// directories are created (default ~/Desktop/Bug_Bounty).
	OutputDir string `json:"output_dir"`
	// NotifyWebhook is a Slack/Discord/generic webhook URL to post a run
	// digest to on completion. Empty disables notifications.
	NotifyWebhook string `json:"notify_webhook"`
	// NotifyType selects the payload format: auto|slack|discord|generic.
	NotifyType string `json:"notify_type"`
	// NotifyOn is when to notify: change|always.
	NotifyOn string `json:"notify_on"`
}

// ConfigFilePath returns the config file location: $RFUF_CONFIG if set,
// otherwise ~/.config/rfuf/config.json.
func ConfigFilePath() string {
	if p := os.Getenv("RFUF_CONFIG"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "rfuf", "config.json")
}

// LoadSettings reads the config file (if present) and overlays environment
// variables on top. It never errors: a missing or malformed file yields the
// zero value, and callers overlay CLI flags afterward.
func LoadSettings() Settings {
	var s Settings
	if path := ConfigFilePath(); path != "" {
		if data, err := os.ReadFile(path); err == nil {
			_ = json.Unmarshal(data, &s)
		}
	}
	if v := os.Getenv("RFUF_OUTPUT_DIR"); v != "" {
		s.OutputDir = v
	}
	if v := os.Getenv("RFUF_NOTIFY_WEBHOOK"); v != "" {
		s.NotifyWebhook = v
	}
	if v := os.Getenv("RFUF_NOTIFY_TYPE"); v != "" {
		s.NotifyType = v
	}
	if v := os.Getenv("RFUF_NOTIFY_ON"); v != "" {
		s.NotifyOn = v
	}
	return s
}

// ResolvePaths resolves per-domain paths under the default output base.
func ResolvePaths(domain string) (*Paths, error) {
	return ResolvePathsWithBase(domain, "")
}

// ResolvePathsWithBase resolves per-domain paths, placing the work directory
// under baseDir. An empty baseDir falls back to ~/Desktop/Bug_Bounty, the
// historical default.
func ResolvePathsWithBase(domain, baseDir string) (*Paths, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("could not get home directory: %v", err)
	}

	goPath := os.Getenv("GOPATH")
	if goPath == "" {
		goPath = filepath.Join(home, "go")
	}
	goBin := filepath.Join(goPath, "bin")

	base := baseDir
	if base == "" {
		base = filepath.Join(home, "Desktop", "Bug_Bounty")
	}
	workDir := filepath.Join(base, domain)

	nucleiTemplates := resolveNucleiTemplates(home)
	gfPatterns := filepath.Join(home, ".gf")
	seclistsWordlist, seclistsWordlistSmall := resolveSeclists(home)
	dnsWordlist := resolveDNSWordlist(home)
	assetnoteWordlist := resolveAssetnote(home)

	// Resolve the bundled nuclei-templates-rfuf overlay directory.
	// We look relative to the running binary's location first (installed
	// path), then fall back to the current working directory (source
	// tree during development). This ensures the path is always absolute
	// regardless of where the pipeline executes from.
	nucleiTemplatesRfuf := resolveNucleiTemplatesRfuf()

	return &Paths{
		NucleiTemplates:          nucleiTemplates,
		NucleiTemplatesRfuf:      nucleiTemplatesRfuf,
		GfPatterns:               gfPatterns,
		WorkDir:                  workDir,
		GoBin:                    goBin,
		SeclistsDirWordlist:      seclistsWordlist,
		SeclistsDirWordlistSmall: seclistsWordlistSmall,
		SeclistsDNSWordlist:      dnsWordlist,
		AssetnoteWordlist:        assetnoteWordlist,
	}, nil
}

func resolveNucleiTemplates(home string) string {
	// 1. Check config file
	configPath := filepath.Join(home, ".config", "nuclei", ".templates-config.json")
	if data, err := os.ReadFile(configPath); err == nil {
		var config map[string]interface{}
		if err := json.Unmarshal(data, &config); err == nil {
			if path, ok := config["nuclei-templates-directory"].(string); ok {
				return path
			}
		}
	}

	// 2. Check common locations (including Kali-specific system paths)
	locs := []string{
		filepath.Join(home, "nuclei-templates"),
		filepath.Join(home, ".local", "nuclei-templates"),
		// Kali Linux system-wide install (via apt)
		"/usr/share/nuclei-templates",
		// Newer Kali / projectdiscovery installs
		filepath.Join(home, ".config", "nuclei", "templates"),
	}
	for _, loc := range locs {
		if _, err := os.Stat(loc); err == nil {
			return loc
		}
	}

	return filepath.Join(home, "nuclei-templates") // Default fallback
}

// resolveNucleiTemplatesRfuf returns the absolute path to the bundled
// nuclei-templates-rfuf/ directory. It checks:
//  1. Alongside the running binary (e.g. ~/.local/share/rfuf/nuclei-templates-rfuf)
//  2. Relative to the current working directory (source-tree dev)
//  3. In $HOME (user clone)
//
// Returns "" if none found — the pipeline handles the empty case gracefully.
func resolveNucleiTemplatesRfuf() string {
	// 1. Check alongside the running binary
	exePath, err := os.Executable()
	if err == nil {
		adjacent := filepath.Join(filepath.Dir(exePath), "nuclei-templates-rfuf")
		if info, err := os.Stat(adjacent); err == nil && info.IsDir() {
			return adjacent
		}
	}

	// 2. Check relative to current working directory (source-tree dev)
	cwd, err := os.Getwd()
	if err == nil {
		candidate := filepath.Join(cwd, "nuclei-templates-rfuf")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
	}

	// 3. Check in $HOME
	home, _ := os.UserHomeDir()
	if home != "" {
		candidate := filepath.Join(home, "nuclei-templates-rfuf")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
	}

	return ""
}

func resolveAssetnote(home string) string {
	locs := []string{
		"/usr/share/wordlists/assetnote/directories.txt",
		filepath.Join(home, "wordlists", "assetnote", "directories.txt"),
		filepath.Join(home, "SecLists", "Discovery", "Web-Content", "assetnote-directories.txt"),
	}
	for _, loc := range locs {
		if _, err := os.Stat(loc); err == nil {
			return loc
		}
	}
	return ""
}

func resolveSeclists(home string) (string, string) {
	medium := []string{
		"/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt",
		"/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
		"/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt",
		filepath.Join(home, "SecLists", "Discovery", "Web-Content", "raft-medium-directories.txt"),
	}
	small := []string{
		"/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-directories.txt",
		"/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt",
		"/usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-directories.txt",
		filepath.Join(home, "SecLists", "Discovery", "Web-Content", "raft-small-directories.txt"),
	}
	firstHit := func(list []string) string {
		for _, p := range list {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
		return ""
	}
	return firstHit(medium), firstHit(small)
}

// resolveDNSWordlist finds a subdomain-prefix wordlist. Web-content
// directory lists must never be used here — appending ".domain" to path
// tokens produces tens of thousands of invalid DNS queries and stalls
// subdomain_brute.
func resolveDNSWordlist(home string) string {
	candidates := []string{
		"/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt",
		"/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
		"/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
		filepath.Join(home, "SecLists", "Discovery", "DNS", "subdomains-top1million-5000.txt"),
		"/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt",
		"/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
		filepath.Join(home, "SecLists", "Discovery", "DNS", "subdomains-top1million-20000.txt"),
		"/usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt",
		"/usr/share/seclists/Discovery/DNS/namelist.txt",
		filepath.Join(home, "SecLists", "Discovery", "DNS", "namelist.txt"),
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
