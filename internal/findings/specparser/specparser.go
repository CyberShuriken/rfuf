package specparser

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Run parses OpenAPI/Swagger specs and sitemaps found in the workDir/api_specs directory
// and extracts all endpoints into workDir/openapi_paths.txt.
func Run(workDir string) error {
	specsDir := filepath.Join(workDir, "api_specs")
	outPath := filepath.Join(workDir, "openapi_paths.txt")

	files, err := os.ReadDir(specsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read specs dir: %w", err)
	}

	out, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer out.Close()
	writer := bufio.NewWriter(out)
	defer writer.Flush()

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		ext := filepath.Ext(file.Name())
		if ext != ".json" && ext != ".yaml" && ext != ".yml" && ext != ".xml" {
			continue
		}

		specPath := filepath.Join(specsDir, file.Name())

		// Handle sitemaps separately
		if ext == ".xml" {
			// Extract URLs from <loc> tags
			cmd := exec.Command("grep", "-oE", "<loc>[^<]+</loc>", specPath)
			output, err := cmd.Output()
			if err != nil {
				continue
			}
			lines := strings.Split(strings.TrimSpace(string(output)), "\n")
			for _, line := range lines {
				if line == "" {
					continue
				}
				url := strings.TrimPrefix(line, "<loc>")
				url = strings.TrimSuffix(url, "</loc>")
				writer.WriteString(url + "\n")
			}
			continue
		}

		// Extract host from filename: <host>.<spec>.json
		// Example: example.com.openapi.json -> https://example.com
		hostFile := file.Name()
		hostFile = strings.TrimSuffix(hostFile, ext)
		hostFile = strings.TrimSuffix(hostFile, ".openapi")
		hostFile = strings.TrimSuffix(hostFile, ".swagger")

		// Restore dots and slashes
		host := strings.ReplaceAll(hostFile, "_", "/")
		if !strings.HasPrefix(host, "http") {
			host = "https://" + host
		}
		host = strings.TrimSuffix(host, "/")

		// Use jq to extract paths from OpenAPI spec
		cmd := exec.Command("jq", "-r", "(.paths // {}) | keys[]", specPath)
		output, err := cmd.Output()
		if err != nil {
			continue
		}

		paths := strings.Split(strings.TrimSpace(string(output)), "\n")
		for _, p := range paths {
			if p == "" {
				continue
			}
			if !strings.HasPrefix(p, "/") {
				continue
			}
			writer.WriteString(host + p + "\n")
		}
	}

	return nil
}
