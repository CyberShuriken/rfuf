package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/CyberShuriken/rfuf/internal/config"
	"github.com/CyberShuriken/rfuf/internal/installer"
	"github.com/CyberShuriken/rfuf/internal/pipeline"
)

var (
	version = "1.0.0"
)

func main() {
	domain := flag.String("d", "", "Target domain for recon")
	resume := flag.Bool("resume", false, "Resume a previous scan")
	showVersion := flag.Bool("v", false, "Show version")
	showHelp := flag.Bool("h", false, "Show help")

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

	// 3. Run Pipeline
	if err := pipeline.Run(*domain, *resume, paths); err != nil {
		fmt.Printf("[!] Pipeline failed: %v\n", err)
		os.Exit(1)
	}
}
