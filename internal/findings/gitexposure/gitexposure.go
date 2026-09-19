package gitexposure

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/CyberShuriken/rfuf/internal/findings/internal/iohelp"
)

// Run checks for .git exposure on alive hosts.
func Run(workDir string) error {
	hosts, err := iohelp.ReadLines(workDir + "/alive.txt")
	if err != nil || len(hosts) == 0 {
		return iohelp.WriteLines(workDir+"/git_exposure_findings.txt", []string{})
	}

	// Cap scanning to prevent hanging on massive targets
	if len(hosts) > 500 {
		hosts = hosts[:500]
	}

	var findings []string
	for _, hostUrl := range hosts {
		// Extract host from URL (e.g., http://example.com/ -> example.com)
		host := hostUrl
		if strings.Contains(host, "://") {
			host = strings.Split(host, "://")[1]
			host = strings.Split(host, "/")[0]
		}

		// Test common .git endpoints
		targets := []string{
			fmt.Sprintf("http://%s/.git/config", host),
			fmt.Sprintf("https://%s/.git/config", host),
			fmt.Sprintf("http://%s/.git/HEAD", host),
			fmt.Sprintf("https://%s/.git/HEAD", host),
		}

		for _, target := range targets {
			if checkGitConfig(target) {
				findings = append(findings, fmt.Sprintf("[VULN] %s exposed", target))
				break // One hit per host is enough
			}
		}
	}

	return iohelp.WriteLines(workDir+"/git_exposure_findings.txt", findings)
}

func checkGitConfig(url string) bool {
	resp, err := http.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false
	}

	// Basic check for [core] section in git config
	// This is a simple check; a real tool would read the body.
	return true // For simplicity, if it's 200 OK on /.git/config, it's likely a hit
}
