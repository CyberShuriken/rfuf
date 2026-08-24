package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CyberShuriken/rfuf/internal/config"
	"github.com/CyberShuriken/rfuf/internal/executor"
	"github.com/CyberShuriken/rfuf/internal/installer"
	"github.com/CyberShuriken/rfuf/internal/installer/sysinstall"
	"github.com/CyberShuriken/rfuf/internal/pipeline"
	"github.com/CyberShuriken/rfuf/internal/scope"
)

var (
	version = "2.4.4"
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

	domain := flag.String("d", "", "Target domain or explicit wildcard scope; bare domain is exact-only")
	resume := flag.Bool("resume", false, "Resume a previous scan (skips already-completed steps AND the installer — trust on-disk binaries)")
	stepTimeout := flag.Duration("step-timeout", 30*time.Minute, "Maximum runtime for each pipeline step (0 disables the limit). Default lowered from 2h so a single hung tool can't block the dashboard; bump to 2h on big targets with `rfuf -d X -step-timeout 2h`.")
	maxTargets := flag.Int("max-targets", 10000, "Maximum URLs retained in the final scoped target streams.")
	maxStageRequests := flag.Int("max-stage-requests", 300, "Per-tool request-rate ceiling passed to scanners that support a rate flag.")
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
		"Researcher username for the X-Bug-Bounty request header required by some programs.")
	testAccountEmail := flag.String("test-account-email", "",
		"Dedicated test-account email for the X-Test-Account-Email request header required by some programs.")
	excludeURLRegex := flag.String("exclude-url-regex", "",
		"Extended regular expression for URLs to exclude before downstream scans (repeat program exclusions safely).")
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

	// 1. Resolve Paths using the normalized root so wildcard and non-wildcard
	// invocations resume into the same per-domain work directory.
	paths, err := config.ResolvePaths(normalizedDomain)
	if err != nil {
		fmt.Printf("[!] Error resolving paths: %v\n", err)
		os.Exit(1)
	}

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
	if *authRequired && cookieValue == "" && bearerValue == "" {
		fmt.Println("[!] authenticated testing was required but no cookie or bearer token was supplied")
		os.Exit(1)
	}
	buildAuthEnv(cookieValue, bearerValue, *bugBountyUsername, *testAccountEmail)
	executor.AuthEnv["RFUF_DOMAIN"] = normalizedDomain
	executor.AuthEnv["RFUF_SCOPE_INPUT"] = parsedScope.Input
	executor.AuthEnv["RFUF_SCOPE_MODE"] = string(parsedScope.Mode)
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
		_ = writeAuthCheckMetadata(paths.WorkDir, true, verified, status, checkErr)
		if checkErr != nil {
			fmt.Printf("[!] Auth check failed (HTTP %d): %v\n", status, checkErr)
			if *authRequired {
				os.Exit(1)
			}
		} else if verified {
			fmt.Printf("[*] Auth check passed (HTTP %d)\n", status)
		} else {
			fmt.Printf("[!] Auth check did not match the expected authenticated response (HTTP %d)\n", status)
			if *authRequired {
				os.Exit(1)
			}
		}
	}

	if strings.TrimSpace(*authCheckURL) == "" {
		_ = writeAuthCheckMetadata(paths.WorkDir, false, false, 0, nil)
	}

	// 3. Start interactsh-client for OOB / blind detection. The allocated
	//    URL is wired into the executor's env so SSRF/RCE/XSS stages can
	//    substitute it into payloads. Skipping is safe: empty RFUF_OOB_URL
	//    means shell `${RFUF_OOB_URL:+...}` expansions evaluate to empty
	//    and the pipeline proceeds without OOB.
	if !*disableInteractsh {
		if *interactshTimeout <= 0 {
			fmt.Println("[*] OOB startup wait disabled; proceeding without interactsh")
		} else if err := startInteractsh(*interactshServer, *interactshTimeout); err != nil {
			fmt.Printf("[!] OOB callbacks unavailable: %v\n", err)
			fmt.Println("    Continuing without OOB detection; use -disable-interactsh to suppress this check.")
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
	if err := pipeline.RunForScope(parsedScope, *resume, paths, *stepTimeout); err != nil {
		fmt.Printf("[!] Pipeline failed: %v\n", err)
		os.Exit(1)
	}
}

// buildAuthEnv populates the executor's AuthEnv map from the -auth-cookie
// and -auth-bearer flags. Stage commands reference these via:
//
//	${RFUF_AUTH_COOKIE:+"--cookie=$RFUF_AUTH_COOKIE"}
//	${RFUF_AUTH_HEADER:+"--headers=Authorization: $RFUF_AUTH_HEADER"}
//
// and the per-tool wrappers translate them into the right CLI flags.
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
		Configured bool   `json:"configured"`
		Verified   bool   `json:"verified"`
		StatusCode int    `json:"status_code,omitempty"`
		Error      string `json:"error,omitempty"`
	}{Configured: configured, Verified: verified, StatusCode: status}
	if checkErr != nil {
		metadata.Error = checkErr.Error()
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
		return false, 0, err
	}
	if cookie := strings.TrimSpace(executor.AuthEnv["RFUF_AUTH_COOKIE"]); cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	if bearer := strings.TrimSpace(executor.AuthEnv["RFUF_AUTH_HEADER"]); bearer != "" {
		req.Header.Set("Authorization", bearer)
	}
	if username := strings.TrimSpace(executor.AuthEnv["RFUF_BUG_BOUNTY_USERNAME"]); username != "" {
		req.Header.Set("X-Bug-Bounty", username)
	}
	if email := strings.TrimSpace(executor.AuthEnv["RFUF_TEST_ACCOUNT_EMAIL"]); email != "" {
		req.Header.Set("X-Test-Account-Email", email)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return false, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return false, resp.StatusCode, err
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
