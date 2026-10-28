package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/CyberShuriken/rfuf/internal/config"
	"github.com/CyberShuriken/rfuf/internal/diffsnap"
	"github.com/CyberShuriken/rfuf/internal/digest"
	"github.com/CyberShuriken/rfuf/internal/executor"
	"github.com/CyberShuriken/rfuf/internal/filter"
	"github.com/CyberShuriken/rfuf/internal/findings"
	"github.com/CyberShuriken/rfuf/internal/installer"
	"github.com/CyberShuriken/rfuf/internal/installer/sysinstall"
	"github.com/CyberShuriken/rfuf/internal/notify"
	"github.com/CyberShuriken/rfuf/internal/pipeline"
	"github.com/CyberShuriken/rfuf/internal/scope"
)

var (
	version = "2.4.10"
)

func main() {
	// Internal, maintenance, and cleanup commands are handled before the
	// normal scan flags are parsed.
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "findings":
			if len(os.Args) != 4 {
				fmt.Fprintln(os.Stderr, "usage: rfuf findings <finder-name> <workdir>")
				os.Exit(2)
			}
			if err := findings.RunFinder(os.Args[2], os.Args[3]); err != nil {
				fmt.Fprintf(os.Stderr, "rfuf findings %s: %v\n", os.Args[2], err)
				os.Exit(1)
			}
			return
		case "filter-testable":
			if err := runFilterTestable(os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "rfuf filter-testable: %v\n", err)
				os.Exit(1)
			}
			return
		case "target-stream":
			if err := runTargetStream(os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "rfuf target-stream: %v\n", err)
				os.Exit(1)
			}
			return
		case "diff-snapshot":
			if len(os.Args) != 3 {
				fmt.Fprintln(os.Stderr, "usage: rfuf diff-snapshot <workdir>")
				os.Exit(2)
			}
			if err := diffsnap.Run(os.Args[2]); err != nil {
				fmt.Fprintf(os.Stderr, "rfuf diff-snapshot: %v\n", err)
				os.Exit(1)
			}
			return
		case "monitor":
			if err := runMonitor(os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "rfuf monitor: %v\n", err)
				os.Exit(1)
			}
			return
		case "preflight":
			if len(os.Args) != 2 {
				fmt.Fprintln(os.Stderr, "usage: rfuf preflight")
				os.Exit(2)
			}
			if err := installer.VerifyToolsPresent(); err != nil {
				fmt.Fprintf(os.Stderr, "rfuf preflight: %v\n", err)
				os.Exit(1)
			}
			return
		case "install":
			installFlags := flag.NewFlagSet("install", flag.ContinueOnError)
			installFlags.SetOutput(os.Stderr)
			nonInteractive := installFlags.Bool("non-interactive", false, "Install the binary without prompting or editing shell startup files")
			if err := installFlags.Parse(os.Args[2:]); err != nil {
				os.Exit(2)
			}
			if len(installFlags.Args()) != 0 {
				fmt.Fprintln(os.Stderr, "usage: rfuf install [--non-interactive]")
				os.Exit(2)
			}
			install := sysinstall.Install
			if *nonInteractive {
				install = sysinstall.InstallNonInteractive
			}
			if err := install(); err != nil {
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
		case "clean":
			cleanDomain := flag.String("d", "", "Target domain to clean workspace for")
			flag.CommandLine.Parse(os.Args[2:])
			if *cleanDomain == "" {
				fmt.Println("Usage: rfuf clean -d <domain>")
				os.Exit(1)
			}
			paths, err := config.ResolvePathsWithBase(*cleanDomain, config.LoadSettings().OutputDir)
			if err != nil {
				fmt.Printf("[!] failed to resolve paths: %v\n", err)
				os.Exit(1)
			}
			if err := pipeline.CleanWorkspace(paths); err != nil {
				fmt.Printf("[!] cleanup failed: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("[+] Workspace for %s cleaned successfully\n", *cleanDomain)
			return
		}
	}

	domain := flag.String("d", "", "Target domain or explicit wildcard scope; bare domain is exact-only")
	resume := flag.Bool("resume", false, "Resume a previous scan (skips already-completed steps AND the installer — trust on-disk binaries)")
	stepTimeout := flag.Duration("step-timeout", 30*time.Minute, "Maximum runtime for each pipeline step (0 disables the limit). Default lowered from 2h so a single hung tool can't block the dashboard; bump to 2h on big targets with `rfuf -d X -step-timeout 2h`.")
	maxTargets := flag.Int("max-targets", 10000, "Maximum URLs retained in the final scoped target streams.")
	maxStageRequests := flag.Int("max-stage-requests", 300, "Per-tool request-rate ceiling passed to scanners that support a rate flag.")
	userWordlist := flag.String("wordlist", "", "Override the default directory wordlist with a specific file path.")
	outputDir := flag.String("output-dir", "", "Base directory for per-domain output (default ~/Desktop/Bug_Bounty; or $RFUF_OUTPUT_DIR / config file).")
	notifyWebhook := flag.String("notify-webhook", "", "Webhook URL to post a run digest to on completion (Slack/Discord/generic; or $RFUF_NOTIFY_WEBHOOK).")
	notifyType := flag.String("notify-type", "", "Notification payload format: auto|slack|discord|generic (default auto).")
	notifyOn := flag.String("notify-on", "", "When to notify: change (only when new subdomains/JS appear) or always (default change).")
	skipInstall := flag.Bool("skip-install", false, "Skip dependency installation entirely (fastest resume path — use only if you trust your $PATH)")

	// Auth mode — injected as env vars into every shell command. Stage
	// commands translate these into per-tool flags via shell wrappers.
	authCookie := flag.String("auth-cookie", "",
		"Cookie value injected into every request (e.g. 'session=abc123def456'). Unlocks the bug surface behind login on the target.")
	authBearer := flag.String("auth-bearer", "",
		"Bearer token injected as Authorization header (e.g. JWT). Use for API-first targets with token auth.")
	authCookieFile := flag.String("auth-cookie-file", "",
		"Read a session cookie value from a local file when -auth-cookie is not supplied.")
	authBearerFile := flag.String("auth-bearer-file", "",
		"Read a bearer token from a local file when -auth-bearer is not supplied.")
	authRequired := flag.Bool("auth-required", false,
		"Refuse to start unless a cookie or bearer session is supplied.")
	secondAuthCookie := flag.String("auth-cookie-b", "", "Optional second authorized test-account cookie; metadata only, never replayed automatically.")
	secondAuthCookieFile := flag.String("auth-cookie-b-file", "", "Read an optional second test-account cookie from a local file; metadata only.")
	secondAuthBearer := flag.String("auth-bearer-b", "", "Optional second authorized test-account bearer token; metadata only, never replayed automatically.")
	secondAuthBearerFile := flag.String("auth-bearer-b-file", "", "Read an optional second test-account bearer token from a local file; metadata only.")
	roleA := flag.String("role-a", "", "Label for the primary test identity or role in the manual validation plan.")
	roleB := flag.String("role-b", "", "Label for the optional second test identity or role in the manual validation plan.")
	repositoryPath := flag.String("repository-path", "", "Optional local repository path for source and supply-chain review planning; not uploaded or scanned automatically.")
	testAPIBaseURL := flag.String("test-api-base-url", "", "Optional authorized test API base URL to reference in manual validation planning; not contacted automatically.")
	bugBountyUsername := flag.String("bug-bounty-username", "",
		"Researcher username for X-HackerOne-Research and legacy X-Bug-Bounty attribution headers.")
	testAccountEmail := flag.String("test-account-email", "",
		"Dedicated test-account email for the X-Test-Account-Email request header required by some programs.")
	excludeURLRegex := flag.String("exclude-url-regex", "",
		"Extended regular expression for URLs to exclude before downstream scans (repeat program exclusions safely).")
	scopeFile := flag.String("scope-file", "",
		"Path to a file of additional in-scope assets (one per line; bare root = exact, *.root = wildcard, # comments). Pins the run to a validated multi-asset program scope so requests and findings stay within it.")
	loginURL := flag.String("login-url", "",
		"Optional login endpoint. RFUF POSTs -login-data here, captures the resulting session cookie(s), and scans authenticated — no need to paste a cookie. Opt-in; unset = unchanged.")
	loginData := flag.String("login-data", "",
		"Request body for -login-url (e.g. 'email=u@x.com&password=p' or a JSON object with -login-content-type application/json).")
	loginContentType := flag.String("login-content-type", "application/x-www-form-urlencoded",
		"Content-Type for -login-data (default form-encoded; use application/json for JSON logins).")
	loginSuccessMarker := flag.String("login-success-marker", "",
		"Optional text expected in the login response to confirm success before trusting the captured session.")
	authCheckURL := flag.String("auth-check-url", "",
		"Optional URL used to verify that supplied auth material reaches an authenticated surface.")
	authCheckMarker := flag.String("auth-check-marker", "",
		"Optional response-text marker expected from -auth-check-url; never printed or stored.")

	// OOB / blind detection. Starts interactsh-client at pipeline boot
	// and wires $RFUF_OOB_URL into SSRF/RCE/XSS payloads.
	interactshServer := flag.String("interactsh-server", "https://oast.fun",
		"interactsh server URL to register with. Default oast.fun (projectdiscovery's public server). Use -disable-interactsh on offline/private scans.")
	interactshTimeout := flag.Duration("interactsh-timeout", 20*time.Second,
		"Maximum time to wait for interactsh-client to print its callback URL. Set to 0 to disable OOB startup waiting.")
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
	parsedScope, err := scope.Parse(*domain)
	if err != nil {
		fmt.Printf("Error: invalid domain scope: %v\n", err)
		os.Exit(1)
	}
	normalizedDomain := parsedScope.RootDomain
	if *maxTargets <= 0 || *maxStageRequests <= 0 {
		fmt.Println("Error: -max-targets and -max-stage-requests must be positive")
		os.Exit(1)
	}

	fmt.Printf("[*] RFUF v%s | target: %s | scope: %s (%s)\n", version, *domain, normalizedDomain, parsedScope.Mode)

	// Load persistent settings (config file + env); CLI flags override.
	settings := config.LoadSettings()
	effOutputDir := firstNonEmpty(*outputDir, settings.OutputDir)

	// 1. Resolve Paths using the normalized root so wildcard and non-wildcard
	// invocations resume into the same per-domain work directory.
	paths, err := config.ResolvePathsWithBase(normalizedDomain, effOutputDir)
	if err != nil {
		fmt.Printf("[!] Error resolving paths: %v\n", err)
		os.Exit(1)
	}
	paths.UserWordlist = *userWordlist

	// 2. Build auth env map (used by executor to inject into every shell).
	//    Only populated when explicitly requested — empty AuthEnv means
	//    unauthenticated scan, which is the historical default.
	cookieValue, err := authValue(*authCookie, *authCookieFile, "cookie")
	if err != nil {
		fmt.Printf("[!] %v\n", err)
		os.Exit(1)
	}
	bearerValue, err := authValue(*authBearer, *authBearerFile, "bearer token")
	if err != nil {
		fmt.Printf("[!] %v\n", err)
		os.Exit(1)
	}
	secondCookieValue, err := authValue(*secondAuthCookie, *secondAuthCookieFile, "second test-account cookie")
	if err != nil {
		fmt.Printf("[!] %v\n", err)
		os.Exit(1)
	}
	secondBearerValue, err := authValue(*secondAuthBearer, *secondAuthBearerFile, "second test-account bearer token")
	if err != nil {
		fmt.Printf("[!] %v\n", err)
		os.Exit(1)
	}
	// Login-replay: acquire a session automatically instead of pasting a cookie.
	if strings.TrimSpace(*loginURL) != "" && cookieValue == "" {
		captured, lerr := performLogin(*loginURL, *loginData, *loginContentType, *loginSuccessMarker)
		if lerr != nil {
			fmt.Printf("[!] login-replay failed: %v\n", lerr)
			if *authRequired {
				os.Exit(1)
			}
		} else {
			cookieValue = captured
			fmt.Println("[*] login-replay: session acquired; scanning authenticated")
		}
	}
	if *authRequired && cookieValue == "" && bearerValue == "" {
		fmt.Println("[!] authenticated testing was required but no cookie or bearer token was supplied")
		os.Exit(1)
	}
	if *authRequired && strings.TrimSpace(*authCheckURL) == "" {
		fmt.Println("[!] -auth-required needs -auth-check-url so RFUF can verify the supplied session before scanning")
		os.Exit(1)
	}
	buildAuthEnv(cookieValue, bearerValue, *bugBountyUsername, *testAccountEmail)
	executor.AuthEnv["RFUF_DOMAIN"] = normalizedDomain
	executor.AuthEnv["RFUF_SCOPE_INPUT"] = parsedScope.Input
	executor.AuthEnv["RFUF_SCOPE_MODE"] = string(parsedScope.Mode)
	if strings.TrimSpace(*scopeFile) != "" {
		extras, serr := readScopeFile(*scopeFile)
		if serr != nil {
			fmt.Printf("[!] invalid -scope-file: %v\n", serr)
			os.Exit(1)
		}
		// Validate every entry via the scope parser; a malformed asset fails loudly.
		if _, verr := parsedScope.WithExtraRoots(extras); verr != nil {
			fmt.Printf("[!] invalid asset in -scope-file: %v\n", verr)
			os.Exit(1)
		}
		if len(extras) > 0 {
			executor.AuthEnv["RFUF_SCOPE_EXTRA"] = strings.Join(extras, ",")
			fmt.Printf("[*] Scope file: %d extra in-scope asset(s) enforced\n", len(extras))
		}
	}
	if err := writeValidationInputsMetadata(paths.WorkDir, secondCookieValue != "", secondBearerValue != "", *roleA, *roleB, *repositoryPath, *testAPIBaseURL); err != nil {
		fmt.Printf("[!] failed to write validation metadata: %v\n", err)
		os.Exit(1)
	}
	executor.AuthEnv["RFUF_MAX_TARGETS"] = fmt.Sprintf("%d", *maxTargets)
	executor.AuthEnv["RFUF_MAX_STAGE_REQUESTS"] = fmt.Sprintf("%d", *maxStageRequests)
	if strings.TrimSpace(*excludeURLRegex) != "" {
		executor.AuthEnv["RFUF_EXCLUDE_URL_REGEX"] = strings.TrimSpace(*excludeURLRegex)
		fmt.Println("[*] URL exclusion regex enabled")
	}
	if strings.TrimSpace(*authCheckMarker) != "" && strings.TrimSpace(*authCheckURL) == "" {
		fmt.Println("[!] -auth-check-marker requires -auth-check-url")
		os.Exit(1)
	}
	if strings.TrimSpace(*authCheckURL) != "" {
		verified, status, checkErr := verifyAuthSession(*authCheckURL, *authCheckMarker)
		executor.AuthEnv["RFUF_AUTH_VERIFIED"] = fmt.Sprintf("%t", verified)
		if err := writeAuthCheckMetadata(paths.WorkDir, cookieValue != "" || bearerValue != "", verified, status, checkErr); err != nil {
			fmt.Printf("[!] failed to write auth-check metadata: %v\n", err)
			os.Exit(1)
		}
		if checkErr != nil {
			fmt.Printf("[!] Auth check failed (HTTP %d): %v\n", status, checkErr)
			if *authRequired {
				if recordErr := pipeline.RecordAuthPreflightFailure(normalizedDomain, paths, checkErr); recordErr != nil {
					fmt.Printf("[!] Could not write authentication failure report: %v\n", recordErr)
				}
				os.Exit(1)
			}
		} else if verified {
			fmt.Printf("[*] Auth check passed (HTTP %d)\n", status)
		} else {
			fmt.Printf("[!] Auth check did not match the expected authenticated response (HTTP %d)\n", status)
			if *authRequired {
				if recordErr := pipeline.RecordAuthPreflightFailure(normalizedDomain, paths, errors.New("auth_check_not_verified")); recordErr != nil {
					fmt.Printf("[!] Could not write authentication failure report: %v\n", recordErr)
				}
				os.Exit(1)
			}
		}
	}

	if strings.TrimSpace(*authCheckURL) == "" {
		if err := writeAuthCheckMetadata(paths.WorkDir, cookieValue != "" || bearerValue != "", false, 0, nil); err != nil {
			fmt.Printf("[!] failed to write auth-check metadata: %v\n", err)
			os.Exit(1)
		}
	}

	// 3. Start interactsh-client for OOB / blind detection. The allocated
	//    URL is wired into the executor's env so SSRF/RCE/XSS stages can
	//    substitute it into payloads. Skipping is safe: empty RFUF_OOB_URL
	//    means shell `${RFUF_OOB_URL:+...}` expansions evaluate to empty
	//    and the pipeline proceeds without OOB.
	if !*disableInteractsh {
		if *interactshTimeout <= 0 {
			fmt.Println("[*] OOB startup wait disabled; proceeding without interactsh")
		} else {
			var oobErr error
			for i := 0; i < 3; i++ {
				if oobErr = startInteractsh(*interactshServer, *interactshTimeout); oobErr == nil {
					break
				}
				if i < 2 {
					fmt.Printf("[!] OOB startup failed (attempt %d/3): %v. Retrying...\n", i+1, oobErr)
					time.Sleep(2 * time.Second)
				}
			}
			if oobErr != nil {
				fmt.Printf("[!] OOB callbacks unavailable after 3 attempts: %v\n", oobErr)
				fmt.Println("    Continuing without OOB detection; use -disable-interactsh to suppress this check.")
			}
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
			if recordErr := pipeline.RecordBootstrapFailure(normalizedDomain, paths, err); recordErr != nil {
				fmt.Printf("[!] Could not write bootstrap failure report: %v\n", recordErr)
			}
			os.Exit(1)
		}
	} else {
		fmt.Println("[*] Checking dependencies...")
		if err := installer.EnsureTools(paths.GoBin); err != nil {
			fmt.Printf("[!] Error ensuring tools: %v\n", err)
			if recordErr := pipeline.RecordBootstrapFailure(normalizedDomain, paths, err); recordErr != nil {
				fmt.Printf("[!] Could not write bootstrap failure report: %v\n", recordErr)
			}
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
	if err := pipeline.RunForScope(parsedScope, *resume, paths, *stepTimeout); err != nil {
		fmt.Printf("[!] Pipeline failed: %v\n", err)
		os.Exit(1)
	}

	// 7. Consolidate results into findings.json and optionally notify.
	runReporting(paths.WorkDir, normalizedDomain, notify.Config{
		Webhook: firstNonEmpty(*notifyWebhook, settings.NotifyWebhook),
		Type:    firstNonEmpty(*notifyType, settings.NotifyType),
		On:      firstNonEmpty(*notifyOn, settings.NotifyOn),
	})
}

// runReporting is the post-run reporting step: it consolidates the scattered
// result files into findings.json and sends an optional notification. A
// failure here must never fail the scan whose output already landed on disk,
// so every error is downgraded to a warning.
func runReporting(workDir, domain string, ncfg notify.Config) {
	dg, derr := digest.Build(workDir, domain)
	if derr != nil {
		fmt.Printf("[!] Warning: could not build findings.json: %v\n", derr)
	} else {
		fmt.Printf("[*] Wrote findings.json (%d submittable, %d informational, %d total line(s); %d new subdomain(s), %d new JS asset(s))\n",
			dg.SubmittableFindings, dg.InformationalFindings, dg.TotalFindings, len(dg.NewSubdomains), len(dg.NewJSAssets))
	}
	if err := notify.Maybe(ncfg, dg); err != nil {
		fmt.Printf("[!] Warning: notification failed: %v\n", err)
	}
}

// firstNonEmpty returns the first argument whose trimmed value is non-empty.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// runMonitor re-runs a normal RFUF scan on a fixed interval, forwarding all
// non-monitor arguments (-d, auth flags, --notify-webhook, …) to each run.
// Change detection and notification are handled by the normal run path: the
// diff_snapshot stage computes deltas and the notifier (default -notify-on
// change) stays quiet until new surface appears.
func runMonitor(args []string) error {
	interval := 6 * time.Hour
	iterations := 0 // 0 == run forever
	var passthrough []string

	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-interval" || a == "--interval":
			if i+1 >= len(args) {
				return errors.New("-interval requires a duration (e.g. 6h)")
			}
			d, err := time.ParseDuration(args[i+1])
			if err != nil {
				return fmt.Errorf("invalid -interval: %w", err)
			}
			interval = d
			i++
		case strings.HasPrefix(a, "-interval=") || strings.HasPrefix(a, "--interval="):
			d, err := time.ParseDuration(a[strings.IndexByte(a, '=')+1:])
			if err != nil {
				return fmt.Errorf("invalid -interval: %w", err)
			}
			interval = d
		case a == "-iterations" || a == "--iterations":
			if i+1 >= len(args) {
				return errors.New("-iterations requires a count")
			}
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n < 0 {
				return fmt.Errorf("invalid -iterations: %q", args[i+1])
			}
			iterations = n
			i++
		case strings.HasPrefix(a, "-iterations=") || strings.HasPrefix(a, "--iterations="):
			n, err := strconv.Atoi(a[strings.IndexByte(a, '=')+1:])
			if err != nil || n < 0 {
				return fmt.Errorf("invalid -iterations: %q", a)
			}
			iterations = n
		default:
			passthrough = append(passthrough, a)
		}
	}

	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot resolve own binary path: %w", err)
	}
	if interval < time.Minute {
		return errors.New("-interval must be at least 1m to avoid hammering the target")
	}

	fmt.Printf("[*] monitor: every %s, %s, forwarding: %s\n",
		interval, iterationsLabel(iterations), strings.Join(passthrough, " "))

	for round := 1; iterations == 0 || round <= iterations; round++ {
		fmt.Printf("\n[*] monitor: starting run %d (%s)\n", round, time.Now().Format(time.RFC3339))
		cmd := exec.Command(self, passthrough...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		if err := cmd.Run(); err != nil {
			fmt.Printf("[!] monitor: run %d exited with error: %v (continuing)\n", round, err)
		}
		if iterations != 0 && round >= iterations {
			break
		}
		fmt.Printf("[*] monitor: sleeping %s until next run\n", interval)
		time.Sleep(interval)
	}
	return nil
}

func iterationsLabel(n int) string {
	if n == 0 {
		return "forever"
	}
	return fmt.Sprintf("%d iteration(s)", n)
}

func runTargetStream(args []string) error {
	flags := flag.NewFlagSet("target-stream", flag.ContinueOnError)
	input := flags.String("input", "", "line-oriented candidate input")
	output := flags.String("output", "", "canonical target output")
	source := flags.String("source", "unknown", "candidate source label")
	status := flags.String("status", "", "JSON stream count report")
	provenance := flags.String("provenance", "", "JSONL target provenance output")
	maxTargets := flags.Int("max-targets", 10000, "maximum unique targets after normalization")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *input == "" || *output == "" || *status == "" || *provenance == "" || flags.NArg() != 0 {
		return errors.New("usage: rfuf target-stream -input FILE -output FILE -source NAME -status FILE -provenance FILE [-max-targets N]")
	}
	scanScope, err := scope.Parse(os.Getenv("RFUF_SCOPE_INPUT"))
	if err != nil {
		return errors.New("scope must be configured before canonicalizing targets")
	}
	if extra := strings.TrimSpace(os.Getenv("RFUF_SCOPE_EXTRA")); extra != "" {
		scanScope, err = scanScope.WithExtraRoots(strings.Split(extra, ","))
		if err != nil {
			return errors.New("invalid RFUF_SCOPE_EXTRA")
		}
	}
	lines := []string{}
	file, err := os.Open(*input)
	if err == nil {
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		readErr := scanner.Err()
		closeErr := file.Close()
		if readErr != nil {
			return fmt.Errorf("read target input: %w", readErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close target input: %w", closeErr)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("open target input: %w", err)
	}
	max := *maxTargets
	if max <= 0 {
		max = 10000
	}
	candidates, counts, err := scope.CanonicalizeStream(lines, *source, scanScope, os.Getenv("RFUF_EXCLUDE_URL_REGEX"), max)
	if err != nil {
		return err
	}
	var targetLines, provenanceLines strings.Builder
	encoder := json.NewEncoder(&provenanceLines)
	for _, candidate := range candidates {
		targetLines.WriteString(candidate.Value)
		targetLines.WriteByte('\n')
		if err := encoder.Encode(candidate); err != nil {
			return err
		}
	}
	statusBytes, err := counts.JSON()
	if err != nil {
		return err
	}
	files := []struct {
		path string
		data []byte
	}{
		{path: *output, data: []byte(targetLines.String())},
		{path: *status, data: append(statusBytes, '\n')},
		{path: *provenance, data: []byte(provenanceLines.String())},
	}
	for _, file := range files {
		path, data := file.path, file.data
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}
		if err := os.WriteFile(path, data, 0644); err != nil {
			return err
		}
	}
	return nil
}

func runFilterTestable(args []string) error {
	filterFlags := flag.NewFlagSet("filter-testable", flag.ContinueOnError)
	filterFlags.SetOutput(os.Stderr)
	highInterest := filterFlags.Bool("high-interest", false, "Allow URLs without query parameters")
	if err := filterFlags.Parse(args); err != nil {
		return err
	}
	parsed := filterFlags.Args()
	if len(parsed) < 1 || len(parsed) > 2 {
		return fmt.Errorf("usage: rfuf filter-testable [--high-interest] <workdir> [input-file]")
	}
	workDir := parsed[0]
	inPath := filepath.Join(workDir, "all_urls_200.txt")
	if len(parsed) == 2 {
		inPath = parsed[1]
		if !filepath.IsAbs(inPath) {
			inPath = filepath.Join(workDir, inPath)
		}
	}
	outPath := filepath.Join(workDir, ".rfuf", "filter-testable.out")
	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return err
	}
	if _, _, _, err := filter.FilterFile(inPath, outPath, *highInterest); err != nil {
		return err
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(data)
	return err
}

// buildAuthEnv populates the executor's AuthEnv map from the -auth-cookie
// and -auth-bearer flags. Stage commands reference these via:
//
//	${RFUF_AUTH_COOKIE:+"--cookie=$RFUF_AUTH_COOKIE"}
//	${RFUF_AUTH_HEADER:+"--headers=Authorization: $RFUF_AUTH_HEADER"}
//
// and the per-tool wrappers translate them into the right CLI flags.
// performLogin POSTs credentials to a login endpoint and returns the captured
// session as a "k1=v1; k2=v2" cookie string, so a scan can authenticate from a
// username/password instead of a hand-pasted cookie. It follows redirects with
// a cookie jar (login flows often 302 to set the session), optionally confirms
// a success marker in the response body, and fails if no cookie was set.
func performLogin(loginURL, data, contentType, marker string) (string, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{
		Jar:     jar,
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
	req, err := http.NewRequest("POST", loginURL, strings.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("login returned status %d", resp.StatusCode)
	}
	if marker != "" && !strings.Contains(string(body), marker) {
		return "", fmt.Errorf("login success marker %q not found in response", marker)
	}
	u, err := url.Parse(loginURL)
	if err != nil {
		return "", err
	}
	cookies := jar.Cookies(u)
	if len(cookies) == 0 {
		return "", errors.New("login succeeded but set no cookies")
	}
	parts := make([]string, 0, len(cookies))
	for _, c := range cookies {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; "), nil
}

// readScopeFile reads a -scope-file: one asset expression per line, with blank
// lines and #-comments ignored. The expressions themselves are validated by the
// caller via scope.WithExtraRoots.
func readScopeFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read scope file: %w", err)
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("scope file %s contains no assets", path)
	}
	return out, nil
}

func authValue(inline, filePath, label string) (string, error) {
	if strings.TrimSpace(inline) != "" {
		return strings.TrimSpace(inline), nil
	}
	if strings.TrimSpace(filePath) == "" {
		return "", nil
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("read auth %s file: %w", label, err)
	}
	value := strings.TrimSpace(string(data))
	if value == "" {
		return "", fmt.Errorf("auth %s file is empty: %s", label, filePath)
	}
	return value, nil
}

func writeValidationInputsMetadata(workDir string, secondCookie, secondBearer bool, roleA, roleB, repositoryPath, testAPIBaseURL string) error {
	metadata := struct {
		SecondCookieConfigured bool   `json:"second_cookie_configured"`
		SecondBearerConfigured bool   `json:"second_bearer_configured"`
		RoleA                  string `json:"role_a,omitempty"`
		RoleB                  string `json:"role_b,omitempty"`
		RepositoryPath         string `json:"repository_path,omitempty"`
		TestAPIBaseURL         string `json:"test_api_base_url,omitempty"`
	}{SecondCookieConfigured: secondCookie, SecondBearerConfigured: secondBearer, RoleA: strings.TrimSpace(roleA), RoleB: strings.TrimSpace(roleB), RepositoryPath: strings.TrimSpace(repositoryPath), TestAPIBaseURL: strings.TrimSpace(testAPIBaseURL)}
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Join(workDir, ".rfuf")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "validation_inputs.json"), append(data, '\n'), 0644)
}

func writeAuthCheckMetadata(workDir string, configured, verified bool, status int, checkErr error) error {
	metadata := struct {
		Configured  bool      `json:"configured"`
		Verified    bool      `json:"verified"`
		Timestamp   time.Time `json:"timestamp"`
		Mode        string    `json:"mode"`
		HealthCheck string    `json:"health_check"`
		StatusCode  int       `json:"status_code,omitempty"`
		ErrorClass  string    `json:"error_class,omitempty"`
	}{Configured: configured, Verified: verified, Timestamp: time.Now().UTC(), StatusCode: status, HealthCheck: "not_requested"}
	switch {
	case !configured:
		metadata.Mode = "public"
	case verified:
		metadata.Mode = "authenticated_verified"
	default:
		metadata.Mode = "authenticated_unverified"
	}
	if checkErr != nil {
		metadata.HealthCheck = "failed"
		if status != 0 {
			metadata.ErrorClass = "unexpected_http_status"
		} else {
			metadata.ErrorClass = "request_failed"
		}
	} else if configured && !verified && status != 0 {
		metadata.HealthCheck = "failed"
		metadata.ErrorClass = "auth_check_not_verified"
	} else if status != 0 && verified {
		metadata.HealthCheck = "verified"
	}
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Join(workDir, ".rfuf")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "auth_check.json"), data, 0644)
}

func verifyAuthSession(checkURL, marker string) (bool, int, error) {
	req, err := http.NewRequest(http.MethodGet, checkURL, nil)
	if err != nil {
		return false, 0, errors.New("invalid_check_url")
	}
	if cookie := strings.TrimSpace(executor.AuthEnv["RFUF_AUTH_COOKIE"]); cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	if bearer := strings.TrimSpace(executor.AuthEnv["RFUF_AUTH_HEADER"]); bearer != "" {
		req.Header.Set("Authorization", bearer)
	}
	if username := strings.TrimSpace(executor.AuthEnv["RFUF_BUG_BOUNTY_USERNAME"]); username != "" {
		req.Header.Set("X-Bug-Bounty", username)
		req.Header.Set("X-HackerOne-Research", username)
	}
	if email := strings.TrimSpace(executor.AuthEnv["RFUF_TEST_ACCOUNT_EMAIL"]); email != "" {
		req.Header.Set("X-Test-Account-Email", email)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return false, 0, errors.New("request_failed")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return false, resp.StatusCode, errors.New("response_read_failed")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return false, resp.StatusCode, fmt.Errorf("unexpected response status")
	}
	if marker != "" && !strings.Contains(string(body), marker) {
		return false, resp.StatusCode, nil
	}
	return true, resp.StatusCode, nil
}

func buildAuthEnv(cookie, bearer, bugBountyUsername, testAccountEmail string) {
	if cookie == "" && bearer == "" && strings.TrimSpace(bugBountyUsername) == "" && strings.TrimSpace(testAccountEmail) == "" {
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
	if strings.TrimSpace(bugBountyUsername) != "" {
		env["RFUF_BUG_BOUNTY_USERNAME"] = strings.TrimSpace(bugBountyUsername)
		fmt.Printf("[*] Bug-bounty researcher header enabled for %s\n", strings.TrimSpace(bugBountyUsername))
	}
	if strings.TrimSpace(testAccountEmail) != "" {
		env["RFUF_TEST_ACCOUNT_EMAIL"] = strings.TrimSpace(testAccountEmail)
		fmt.Println("[*] Test-account email header enabled")
	}
	executor.AuthEnv = env
}

// startInteractsh allocates a unique OOB callback URL by spawning
// interactsh-client in the background. interactsh-client prints the
// allocated URL on its first stdout line — we parse it, set
// executor.OOBURL, and let the client keep running until pipeline finish
// (stopInteractsh kills it).
func startInteractsh(server string, startupTimeout time.Duration) error {
	if _, err := exec.LookPath("interactsh-client"); err != nil {
		return fmt.Errorf("interactsh-client not on PATH (run without -disable-interactsh only after `rfuf -d X` once on a fresh install)")
	}
	cmd := exec.Command("interactsh-client",
		"-server", server,
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
			if strings.Contains(line, ".oast.fun") || (strings.Contains(line, "https://") && strings.Contains(line, ".oast.fun")) {
				candidate := strings.TrimSpace(line)
				words := strings.Fields(candidate)
				if len(words) > 0 {
					candidate = words[len(words)-1]
				}
				if !strings.HasPrefix(candidate, "http") {
					candidate = "https://" + candidate
				}
				select {
				case urlCh <- candidate:
				default:
				}
				return
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
	case <-time.After(startupTimeout):
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("interactsh-client did not print URL within %s; use -interactsh-timeout 0 or -disable-interactsh if OOB callbacks are unavailable", startupTimeout)
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
