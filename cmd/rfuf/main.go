package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CyberShuriken/rfuf/internal/config"
	"github.com/CyberShuriken/rfuf/internal/executor"
	"github.com/CyberShuriken/rfuf/internal/installer"
	"github.com/CyberShuriken/rfuf/internal/installer/sysinstall"
	"github.com/CyberShuriken/rfuf/internal/pipeline"
)

var (
	version = "2.1.0"
)

func main() {
	// Subcommand dispatch: `rfuf install` and `rfuf update` are handled
	// before flag parsing so neither flow needs -d, -resume, -v, or -h.
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "install":
			if err := sysinstall.Install(); err != nil {
				fmt.Printf("[!] install failed: %v\n", err)
				os.Exit(1)
			}
			return
		case "update":
			// Rebuild the binary in-place at ~/.local/share/rfuf/rfuf
			// (the path `rfuf install` placed it). No shell prompt, no
			// rc-file patch — strictly the "I just rebuilt from source
			// and want the new code on PATH" verb.
			if err := sysinstall.RebuildBinary(); err != nil {
				fmt.Printf("[!] update failed: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}

	domain := flag.String("d", "", "Target domain for recon")
	resume := flag.Bool("resume", false, "Resume a previous scan (skips already-completed steps AND the installer — trust on-disk binaries)")
	stepTimeout := flag.Duration("step-timeout", 30*time.Minute, "Maximum runtime for each pipeline step (0 disables the limit). Default lowered from 2h so a single hung tool can't block the dashboard; bump to 2h on big targets with `rfuf -d X -step-timeout 2h`.")
	skipInstall := flag.Bool("skip-install", false, "Skip dependency installation entirely (fastest resume path — use only if you trust your $PATH)")

	// Auth mode — injected as env vars into every shell command. Stage
	// commands translate these into per-tool flags via shell wrappers.
	authCookie := flag.String("auth-cookie", "",
		"Cookie value injected into every request (e.g. 'session=abc123def456'). Unlocks the bug surface behind login on the target.")
	authBearer := flag.String("auth-bearer", "",
		"Bearer token injected as Authorization header (e.g. JWT). Use for API-first targets with token auth.")

	// OOB / blind detection. Starts interactsh-client at pipeline boot
	// and wires $RFUF_OOB_URL into SSRF/RCE/XSS payloads.
	interactshServer := flag.String("interactsh-server", "https://oast.fun",
		"interactsh server URL to register with. Default oast.fun (projectdiscovery's public server). Use -disable-interactsh on offline/private scans.")
	disableInteractsh := flag.Bool("disable-interactsh", false,
		"Skip starting interactsh-client. Use on offline/private scans or when OOB callbacks are out of scope.")

	showVersion := flag.Bool("v", false, "Show version")
	showHelp := flag.Bool("h", false, "Show help")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "rfuf — Recon Faster U Fool (v%s)\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  rfuf -d <domain> [flags]   Run the recon pipeline against a domain\n")
		fmt.Fprintf(os.Stderr, "  rfuf install               Install rfuf to ~/.local/share/rfuf and configure PATH\n")
		fmt.Fprintf(os.Stderr, "  rfuf update                Rebuild the installed binary from the current source tree\n\n")
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

	// 2. Build auth env map (used by executor to inject into every shell).
	//    Only populated when explicitly requested — empty AuthEnv means
	//    unauthenticated scan, which is the historical default.
	buildAuthEnv(*authCookie, *authBearer)

	// 3. Start interactsh-client for OOB / blind detection. The allocated
	//    URL is wired into the executor's env so SSRF/RCE/XSS stages can
	//    substitute it into payloads. Skipping is safe: empty RFUF_OOB_URL
	//    means shell `${RFUF_OOB_URL:+...}` expansions evaluate to empty
	//    and the pipeline proceeds without OOB.
	if !*disableInteractsh {
		if err := startInteractsh(*interactshServer); err != nil {
			fmt.Printf("[!] interactsh start failed: %v — proceeding without OOB\n", err)
		}
		defer stopInteractsh()
	}

	// 4. Ensure Tools. -resume implies -skip-install: re-running the
	// installer on every resume can be expensive (re-clones repos, hits
	// sudo password prompts that fail silently in non-interactive shells,
	// rebuilds go binaries we already have) and is almost never what the
	// user wanted — they just want to pick up where the pipeline stopped.
	//
	// The -skip-install flag covers the corner case where a user wants
	// the explicit install-skip on a fresh run too (debugging, CI).
	if *resume || *skipInstall {
		fmt.Println("[*] Resume mode — skipping dependency installer (trusting on-disk tools)")
		if err := installer.VerifyToolsPresent(); err != nil {
			fmt.Printf("[!] %v\n", err)
			fmt.Println("[!] Drop -resume (or -skip-install) to run the installer once.")
			os.Exit(1)
		}
	} else {
		fmt.Println("[*] Checking dependencies...")
		if err := installer.EnsureTools(paths.GoBin); err != nil {
			fmt.Printf("[!] Error ensuring tools: %v\n", err)
			os.Exit(1)
		}

		// 5. Ensure Seclists — same reasoning: cloning SecLists is
		// multi-hundred-MB and never needs to repeat on resume.
		seclistsPath, err := installer.EnsureSeclists()
		if err != nil {
			fmt.Printf("[!] Warning: %v\n", err)
		} else {
			paths.SeclistsDirWordlist = seclistsPath
		}
	}

	// 6. Run Pipeline
	if err := pipeline.Run(*domain, *resume, paths, *stepTimeout); err != nil {
		fmt.Printf("[!] Pipeline failed: %v\n", err)
		os.Exit(1)
	}
}

// buildAuthEnv populates the executor's AuthEnv map from the -auth-cookie
// and -auth-bearer flags. Stage commands reference these via:
//   ${RFUF_AUTH_COOKIE:+"--cookie=$RFUF_AUTH_COOKIE"}
//   ${RFUF_AUTH_HEADER:+"--headers=Authorization: $RFUF_AUTH_HEADER"}
// and the per-tool wrappers translate them into the right CLI flags.
func buildAuthEnv(cookie, bearer string) {
	if cookie == "" && bearer == "" {
		return
	}
	env := map[string]string{}
	if cookie != "" {
		env["RFUF_AUTH_COOKIE"] = cookie
		fmt.Printf("[*] Auth mode: cookie value will be injected (%d chars)\n", len(cookie))
	}
	if bearer != "" {
		env["RFUF_AUTH_HEADER"] = "Bearer " + bearer
		fmt.Printf("[*] Auth mode: bearer token will be injected (%d chars)\n", len(bearer))
	}
	executor.AuthEnv = env
}

// startInteractsh allocates a unique OOB callback URL by spawning
// interactsh-client in the background. interactsh-client prints the
// allocated URL on its first stdout line — we parse it, set
// executor.OOBURL, and let the client keep running until pipeline finish
// (stopInteractsh kills it).
func startInteractsh(server string) error {
	if _, err := exec.LookPath("interactsh-client"); err != nil {
		return fmt.Errorf("interactsh-client not on PATH (run without -disable-interactsh only after `rfuf -d X` once on a fresh install)")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := exec.CommandContext(ctx, "interactsh-client",
		"-server", server,
		"-no-http-server",
		"-v",
	)
	stdoutR, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	cmd.Stderr = cmd.Stdout // merge stderr into stdout capture

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start interactsh-client: %w", err)
	}

	// Scan the first ~50 lines for the URL pattern. interactsh-client
	// prints it within the first second of startup.
	urlCh := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdoutR)
		for scanner.Scan() {
			line := scanner.Text()
			if i := strings.Index(line, "https://"); i >= 0 {
				candidate := strings.TrimSpace(line[i:])
				// Strip trailing punctuation/quotes that may trail
				candidate = strings.TrimRight(candidate, " \t\r\n,;]})\"]'")
				if strings.Contains(candidate, ".oast.fun") || strings.Contains(candidate, ".") {
					select {
					case urlCh <- candidate:
					default:
					}
					return
				}
			}
		}
	}()

	select {
	case url := <-urlCh:
		executor.OOBURL = url
		fmt.Printf("[*] OOB callback URL: %s\n", url)
		// detach the running process — keep it alive for the pipeline duration
		go func() { _ = cmd.Wait() }()
		return nil
	case <-time.After(8 * time.Second):
		_ = cmd.Process.Kill()
		return fmt.Errorf("interactsh-client did not print URL within 8s")
	}
}

// stopInteractsh kills any running interactsh-client process tree. Called
// from defer in main so the callback server doesn't outlive the scan.
func stopInteractsh() {
	if executor.OOBURL == "" {
		return
	}
	// pkill is harmless if no interactsh-client is running.
	_ = exec.Command("pkill", "-f", "interactsh-client").Run()
}
