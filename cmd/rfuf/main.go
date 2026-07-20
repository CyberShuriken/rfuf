package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/CyberShuriken/rfuf/internal/config"
	"github.com/CyberShuriken/rfuf/internal/installer"
	"github.com/CyberShuriken/rfuf/internal/installer/sysinstall"
	"github.com/CyberShuriken/rfuf/internal/pipeline"
)

var (
	version = "2.0.0"
)

func main() {
	// Subcommand dispatch: `rfuf install` is handled before flag parsing
	// so the install flow does not need -d, -resume, -v, or -h.
	if len(os.Args) >= 2 && os.Args[1] == "install" {
		if err := sysinstall.Install(); err != nil {
			fmt.Printf("[!] install failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	domain := flag.String("d", "", "Target domain for recon")
	resume := flag.Bool("resume", false, "Resume a previous scan")
	showVersion := flag.Bool("v", false, "Show version")
	showHelp := flag.Bool("h", false, "Show help")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "rfuf — Recon Faster U Fool (v%s)\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  rfuf -d <domain> [flags]   Run the recon pipeline against a domain\n")
		fmt.Fprintf(os.Stderr, "  rfuf install               Install rfuf system-wide to /opt/rfuf and configure PATH\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("rfuf version %s\n", version)
		os.Exit(0)
	}

	if *showHelp || (*domain == "" && flag.NFlag() == 0) {
		flag.Usage()
		os.Exit(0)
	}

	if *domain == "" {
		fmt.Println("Error: domain (-d) is required")
		flag.Usage()
		os.Exit(1)
	}

	fmt.Printf("[*] Starting RFUF for %s\n", *domain)

	// 1. Resolve Paths
	paths, err := config.ResolvePaths(*domain)
	if err != nil {
		fmt.Printf("[!] Error resolving paths: %v\n", err)
		os.Exit(1)
	}

	// 2. Ensure Tools
	fmt.Println("[*] Checking dependencies...")
	if err := installer.EnsureTools(paths.GoBin); err != nil {
		fmt.Printf("[!] Error ensuring tools: %v\n", err)
		os.Exit(1)
	}

	// 3. Ensure Seclists (V2)
	seclistsPath, err := installer.EnsureSeclists()
	if err != nil {
		fmt.Printf("[!] Warning: %v\n", err)
	} else {
		paths.SeclistsDirWordlist = seclistsPath
	}

	// 4. Run Pipeline
	if err := pipeline.Run(*domain, *resume, paths); err != nil {
		fmt.Printf("[!] Pipeline failed: %v\n", err)
		os.Exit(1)
	}
}
