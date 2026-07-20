package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Paths struct {
	NucleiTemplates     string
	GfPatterns          string
	WorkDir             string
	GoBin               string
	SeclistsDirWordlist string
}

func ResolvePaths(domain string) (*Paths, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("could not get home directory: %v", err)
	}

	goPath := os.Getenv("GOPATH")
	if goPath == "" {
		goPath = filepath.Join(home, "go")
	}
	goBin := filepath.Join(goPath, "bin")

	workDir := filepath.Join(home, "Desktop", "Bug_Bounty", domain)

	nucleiTemplates := resolveNucleiTemplates(home)
	gfPatterns := filepath.Join(home, ".gf")
	seclistsWordlist := resolveSeclists(home)

	return &Paths{
		NucleiTemplates:     nucleiTemplates,
		GfPatterns:          gfPatterns,
		WorkDir:             workDir,
		GoBin:               goBin,
		SeclistsDirWordlist: seclistsWordlist,
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

	// 2. Check common locations
	locs := []string{
		filepath.Join(home, "nuclei-templates"),
		filepath.Join(home, ".local", "nuclei-templates"),
	}
	for _, loc := range locs {
		if _, err := os.Stat(loc); err == nil {
			return loc
		}
	}

	return filepath.Join(home, "nuclei-templates") // Default fallback
}

func resolveSeclists(home string) string {
	paths := []string{
		"/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt",
		"/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
		"/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt",
		filepath.Join(home, "SecLists", "Discovery", "Web-Content", "raft-medium-directories.txt"),
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	return "" // Return empty, installer will handle installation
}
