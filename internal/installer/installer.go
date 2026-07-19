package installer

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Tool struct {
	Name           string
	InstallCommand string
	CheckBinary    string
}

func GetRequiredTools(goBin string) []Tool {
	return []Tool{
		{"subfinder", "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "subfinder"},
		{"assetfinder", "go install github.com/tomnomnom/assetfinder@latest", "assetfinder"},
		{"amass", "go install -v github.com/owasp-amass/amass/v4/cmd/amass@master", "amass"},
		{"dnsx", "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest", "dnsx"},
		{"subzy", "go install -v github.com/PentestPad/subzy@latest", "subzy"},
		{"nuclei", "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "nuclei"},
		{"httpx", "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest", "httpx"},
		{"katana", "go install github.com/projectdiscovery/katana/cmd/katana@latest", "katana"},
		{"trufflehog", fmt.Sprintf("curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b %s", goBin), "trufflehog"},
		{"gf", "go install github.com/tomnomnom/gf@latest", "gf"},
		{"Gxss", "go install github.com/KathanP19/Gxss@latest", "Gxss"},
		{"dalfox", "go install github.com/hahwul/dalfox/v2@latest", "dalfox"},
		{"sqlmap", "sudo apt update && sudo apt install -y sqlmap", "sqlmap"},
	}
}

func EnsureTools(goBin string) error {
	// 1. Check Go
	if _, err := exec.LookPath("go"); err != nil {
		return fmt.Errorf("Go is not installed. Install it first: sudo apt install -y golang-go")
	}

	// 2. Setup PATH
	path := os.Getenv("PATH")
	if !strings.Contains(path, goBin) {
		newPath := goBin + ":" + path
		os.Setenv("PATH", newPath)
		fmt.Printf("[*] Added %s to current PATH\n", goBin)
		
		home, _ := os.UserHomeDir()
		zshrc := filepath.Join(home, ".zshrc")
		exportLine := fmt.Sprintf("export PATH=\"%s:$PATH\"", goBin)
		
		if content, err := os.ReadFile(zshrc); err == nil {
			if !strings.Contains(string(content), exportLine) {
				f, _ := os.OpenFile(zshrc, os.O_APPEND|os.O_WRONLY, 0644)
				f.WriteString("\n" + exportLine + "\n")
				f.Close()
				fmt.Println("[*] Added Go bin path to ~/.zshrc")
			}
		} else {
			os.WriteFile(zshrc, []byte(exportLine+"\n"), 0644)
			fmt.Println("[*] Created ~/.zshrc and added Go bin path")
		}
	}

	// 3. Install tools
	for _, t := range GetRequiredTools(goBin) {
		if _, err := exec.LookPath(t.CheckBinary); err != nil {
			fmt.Printf("[*] Installing %s...\n", t.Name)
			cmd := exec.Command("bash", "-c", t.InstallCommand)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("failed to install %s: %v", t.Name, err)
			}
			if t.Name == "nuclei" {
				exec.Command("nuclei", "-update-templates").Run()
			}
		}
	}

	// 4. GF Patterns
	home, _ := os.UserHomeDir()
	gfDir := filepath.Join(home, ".gf")
	if _, err := os.Stat(gfDir); os.IsNotExist(err) {
		fmt.Println("[*] Installing GF patterns...")
		cmd := exec.Command("git", "clone", "https://github.com/1ndianl33t/Gf-Patterns", gfDir)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to clone gf patterns: %v", err)
		}
	}

	return nil
}
