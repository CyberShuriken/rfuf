package pipeline

import (
	"fmt"
	"time"
	"github.com/CyberShuriken/rfuf/internal/config"
	"github.com/CyberShuriken/rfuf/internal/scope"
)

type Step struct {
	ID      string
	Command string
	Tool    string
	Type    string
	Deps    []string
	Timeout time.Duration
}

func GetStepsForScope(scanScope scope.Scope, paths *config.Paths) []Step {
	domain := scanScope.RootDomain
	// ... other logic ...
	return []Step{
		{"setup_directories", fmt.Sprintf("mkdir -p %s", paths.WorkDir), "default", "default", nil, 0},
		{"subfinder", "subfinder -d " + domain + " -all -o subfinder.txt", "subfinder", "default", []string{"setup_directories"}, 0},
		{"assetfinder", "assetfinder --subs-only " + domain + " > assetfinder.txt", "assetfinder", "default", []string{"setup_directories"}, 0},
		{"crtsh", fmt.Sprintf("curl -s \"https://crt.sh/?q=%%25.%s&output=json\" | jq -r '.[] | .name_value' | sort -u > crtsh.txt", domain), "curl", "default", []string{"setup_directories"}, 0},
		{"merge_subs", "touch subfinder.txt assetfinder.txt crtsh.txt; cat subfinder.txt assetfinder.txt crtsh.txt | sort -u > subs.txt", "cat", "default", []string{"subfinder", "assetfinder", "crtsh"}, 0},
	}
}
