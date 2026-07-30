package pipeline

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/CyberShuriken/rfuf/internal/checkpoint"
	"github.com/CyberShuriken/rfuf/internal/cli"
	"github.com/CyberShuriken/rfuf/internal/config"
	"github.com/CyberShuriken/rfuf/internal/executor"
	"github.com/CyberShuriken/rfuf/internal/summary"
)

// pickWordlist prefers the small, curated Seclists raft-small-directories.txt.
// If it's missing on disk (rare — the user cloned SecLists manually), fall
// back to the medium list. Returns "" if neither exists, in which case the
// caller treats the dirbrute stage as a no-op.
func pickWordlist(paths *config.Paths) string {
	if paths.SeclistsDirWordlistSmall != "" {
		return paths.SeclistsDirWordlistSmall
	}
	return paths.SeclistsDirWordlist
}

type Step struct {
	ID      string
	Command string
	Type    string // "default", "grep"
	Deps    []string
}

var (
	uiLock sync.Mutex

	// nucleiOptimized provides better performance for large scans
	nucleiOptimized = " -rl 300 -c 50 -bs 25 -timeout 5 -silent -stats -stats-interval 30"

	// maxScanTargets caps gf/grep output
	maxScanTargets = 5000

	// sqlmapTargetCap is the per-pipeline ceiling for sqlmap. 300 is the
	// sweet spot for batch SQLi without per-target tuning — beyond that the
	// batch output is dominated by time-based blind false positives against
	// random Cloudflare error responses.
	sqlmapTargetCap = 300

	// sqlmapHighSignalParams is a regex over query-parameter *names* that
	// historically yield data when injected. Filtering sqli_targets to
	// these cuts time-based blind noise by ~70 % in bb-methodology
	// benchmarks. The names are case-insensitive; we anchor on [?&] so
	// file extensions and path segments don't match.
	sqlmapHighSignalParams = "[?&](id|uid|user|account|order|doc|product|category|page|article|comment|msg|post|search|query|sort|filter|view|file|path|load|page_id|item_id|news_id|report_id|invoice)="

	// ghauriTargetCap mirrors sqlmapTargetCap for the modern blind-SQLi tool.
	// ghauri's default confuses Cloudflare error pages for boolean-blind hits,
	// so we cap sharply and pair with --technique BT to skip error/stacked.
	ghauriTargetCap = 100
)

func GetSteps(domain string, paths *config.Paths) []Step {
	domainEscaped := strings.ReplaceAll(domain, ".", "\\.")
	wordlist := pickWordlist(paths)

	return []Step{
		{"setup_directories", fmt.Sprintf("mkdir -p %s", paths.WorkDir), "default", nil},
		{"subfinder", fmt.Sprintf("subfinder -d %s -all -o subfinder.txt", domain), "default", []string{"setup_directories"}},
		{"assetfinder", fmt.Sprintf("assetfinder --subs-only %s > assetfinder.txt", domain), "default", []string{"setup_directories"}},
		{"amass_enum", fmt.Sprintf("amass enum -passive -norecursive -timeout 20 -d %s -o amass_raw.txt", domain), "default", []string{"setup_directories"}},
		{"amass_parse", fmt.Sprintf("awk '{print $1}' amass_raw.txt | grep \"%s\" | sort -u > amass_sub.txt", domain), "grep", []string{"amass_enum"}},
		{"merge_subs", "cat subfinder.txt assetfinder.txt amass_sub.txt | sort -u > subs.txt", "default", []string{"subfinder", "assetfinder", "amass_parse"}},
		{"dnsx_resolve", "dnsx -l subs.txt -silent -o live_subs.txt", "default", []string{"merge_subs"}},
		{"subzy_takeover", "subzy run --targets live_subs.txt --vuln | tee subzy_vulnerable.txt", "default", []string{"dnsx_resolve"}},
		{"extract_takeover_targets", fmt.Sprintf("grep \"VULNERABLE\" subzy_vulnerable.txt | grep -oE '[a-zA-Z0-9._-]+\\.%s' | sort -u > takeover_targets.txt", domainEscaped), "grep", []string{"subzy_takeover"}},
		{"validate_takeovers", fmt.Sprintf("nuclei -l takeover_targets.txt -t %s/http/takeovers/ %s -o validated_takeovers.txt", paths.NucleiTemplates, nucleiOptimized), "default", []string{"extract_takeover_targets"}},
		{"httpx_probe", "httpx -l live_subs.txt -silent -o alive.txt", "default", []string{"dnsx_resolve"}},
		{"nuclei_exposures", fmt.Sprintf("nuclei -l alive.txt -tags token-spray,exposure,config -severity medium,high,critical %s -o credentials_found.txt", nucleiOptimized), "default", []string{"httpx_probe"}},
		{"nuclei_misconfigs", fmt.Sprintf("nuclei -l alive.txt -tags misconfig,exposure,panel %s -o misconfigs.txt", nucleiOptimized), "default", []string{"httpx_probe"}},
		{"nuclei_auth_scan", fmt.Sprintf("nuclei -l alive.txt -tags jwt,auth-bypass,default-login %s -o auth_results.txt", nucleiOptimized), "default", []string{"httpx_probe"}},
		// GraphQL templates are maintained across multiple directories in nuclei-templates.
		// Filter by tag instead of a layout-dependent path (the old
		// http/exposed-panels/graphql path no longer exists in current releases).
		{"nuclei_graphql_scan", fmt.Sprintf("nuclei -l alive.txt -tags graphql %s -o graphql_exposed.txt", nucleiOptimized), "default", []string{"httpx_probe"}},
		{"katana_crawl", "katana -list alive.txt -jc -kf all -d 3 -fs rdn -o katana_urls.txt", "default", []string{"httpx_probe"}},
		{"clean_urls", fmt.Sprintf("grep -Ei '^https?://([a-zA-Z0-9-]+\\.)*%s' katana_urls.txt | grep -Ev '\\.(css|js|png|jpg|jpeg|gif|pdf|svg|ico)($|\\?)' | sed 's/\\\\$//' | sort -u > clean_katana_urls.txt", domainEscaped), "grep", []string{"katana_crawl"}},
		{"trufflehog_scan", "trufflehog filesystem clean_katana_urls.txt --only-verified > trufflehog_results.txt", "default", []string{"clean_urls"}},
		{"grep_secrets", "grep -Ei \"api_key|apikey|secret|token|password|aws_key|bearer\" clean_katana_urls.txt | sort -u > potential_secrets.txt", "grep", []string{"clean_urls"}},
		{"gau_urls", "cat live_subs.txt | gau --threads 5 --subs | tee gau_urls.txt", "default", []string{"dnsx_resolve"}},
		{"wayback_urls", "cat live_subs.txt | waybackurls | tee wayback_urls.txt", "default", []string{"dnsx_resolve"}},
		{"merge_all_urls", "cat gau_urls.txt wayback_urls.txt clean_katana_urls.txt | sort -u > all_urls.txt", "default", []string{"gau_urls", "wayback_urls", "clean_urls"}},

		// URL dedup. all_urls.txt can balloon to 100k+ entries from
		// gau + wayback + katana; uro collapses the noise down to unique
		// endpoints so every downstream gf + nuclei stage runs faster.
		{"uro_dedup", "if command -v uro >/dev/null 2>&1; then uro < all_urls.txt > uro_urls.txt; cp uro_urls.txt all_urls.txt; else sort -u all_urls.txt -o all_urls.txt; fi", "grep", []string{"merge_all_urls"}},

		// 200-only filter for the vuln scanners. all_urls.txt contains
		// historical URLs from gau/wayback that may no longer exist;
		// feeding those to sqlmap/dalfox/nuclei wastes time and produces
		// false-positive "Parameter might be injectable" noise from timeouts.
		// httpx -mc 200 keeps only endpoints that respond OK at scan time.
		// manual_review_queue below deliberately keeps the full stream so the
		// hunter can see *all* historically-interesting paths, not just live ones.
		{"url_filter_alive", "httpx -l all_urls.txt -silent -status-code -mc 200 -o all_urls_200.txt", "grep", []string{"uro_dedup"}},
		{"sqli_targets", fmt.Sprintf("{ gf sqli all_urls_200.txt; grep -Ei '%s' all_urls_200.txt; } | sort -u | head -n %d > sqli_targets.txt", sqlmapHighSignalParams, sqlmapTargetCap), "grep", []string{"url_filter_alive"}},
		{"sqlmap_scan", "sqlmap -m sqli_targets.txt --batch --random-agent --flush-session --technique=BEUSTQ --level=3 --risk=1 --output-dir=./sqlmap_results", "default", []string{"sqli_targets"}},
		{"xss_targets", "{ gf xss all_urls_200.txt; grep -Ei \"q=|search|query|keyword|text|name|email|msg|redirect|url=\" all_urls_200.txt; } | sort -u > xss_targets.txt", "grep", []string{"url_filter_alive"}},
		{"xss_scan", "cat xss_targets.txt | Gxss -p khXSS | dalfox pipe --output xss_vulnerabilities.txt", "default", []string{"xss_targets"}},
		{"rce_targets", fmt.Sprintf("{ gf rce all_urls_200.txt; grep -Ei '[?&](cmd|exec|command|ping|daemon|upload|shell|code)=' all_urls_200.txt; } | sort -u | head -n %d > rce_targets.txt", maxScanTargets), "grep", []string{"url_filter_alive"}},
		{"rce_scan", fmt.Sprintf("nuclei -l rce_targets.txt -tags rce -severity high,critical %s -o nuclei_rce_rce.txt", nucleiOptimized), "default", []string{"rce_targets"}},
		{"idor_targets", fmt.Sprintf("{ gf idor all_urls_200.txt; grep -Ei '[?&](id|account|order|doc|profile|booking|reservation|uid|user_id)=' all_urls_200.txt; } | sort -u | head -n %d > idor_targets.txt", maxScanTargets), "grep", []string{"url_filter_alive"}},
		{"idor_scan", fmt.Sprintf("nuclei -l idor_targets.txt -tags idor %s -o idor_vulnerabilities.txt", nucleiOptimized), "default", []string{"idor_targets"}},
		{"ssrf_targets", "gf ssrf all_urls_200.txt > ssrf_targets.txt; grep -Ei \"url=|uri=|path=|dest=|redirect=|callback=|webhook=|src=|fetch=|proxy=|target=\" all_urls_200.txt >> ssrf_targets.txt; sort -u ssrf_targets.txt -o ssrf_targets.txt", "grep", []string{"url_filter_alive"}},
		{"ssrf_scan", fmt.Sprintf("nuclei -l ssrf_targets.txt -tags ssrf %s -o ssrf_vulnerabilities.txt", nucleiOptimized), "default", []string{"ssrf_targets"}},
		{"redirect_targets", fmt.Sprintf("gf redirect all_urls_200.txt | sort -u | head -n %d > redirect_targets.txt", maxScanTargets), "grep", []string{"url_filter_alive"}},
		{"redirect_scan", fmt.Sprintf("nuclei -l redirect_targets.txt -tags redirect %s -o open_redirect_results.txt", nucleiOptimized), "default", []string{"redirect_targets"}},
		{"lfi_targets", "gf lfi all_urls_200.txt > lfi_targets.txt; sort -u lfi_targets.txt -o lfi_targets.txt", "grep", []string{"url_filter_alive"}},
		{"lfi_scan", fmt.Sprintf("nuclei -l lfi_targets.txt -tags lfi %s -o lfi_results.txt", nucleiOptimized), "default", []string{"lfi_targets"}},
		{"cors_check", "while read -r url; do curl -s -H \"Origin: https://evil.com\" -I \"$url\" | grep -qi \"access-control-allow-origin: https://evil.com\" && echo \"[VULN] $url\"; done < alive.txt > cors_findings.txt", "grep", []string{"httpx_probe"}},
		// Fast ffuf pass. Per-host bash loop is gone — a single ffuf invocation
		// with two wordlists (-w hosts.txt:HOST, -w words.txt:WORD) fans out
		// across all hosts in one process, shares ffuf's internal connection
		// pool, and respects -t/-maxtime globally. Discovery accepts
		// 200/301/302/403 so admin panels + .git/.env behind 403 aren't
		// dropped; the verify step below prunes to 200-only for downstream
		// use. Recursion depth 2 catches /admin/FUZZ → /admin/login/FUZZ.
		{"dirbrute_ffuf", fmt.Sprintf("mkdir -p ffuf_results; if [ -n \"%s\" ]; then ffuf -w alive.txt:HOST -w %s:WORD -u \"HOST/CODE:WORD\" -mc 200,301,302,403 -ac -t 50 -maxtime 600 -recursion -recursion-depth 2 -o ffuf_results/all.json -of json -s; jq -r '.results[]? | .url' ffuf_results/all.json 2>/dev/null | sort -u > ffuf_dirs_raw.txt; else : > ffuf_dirs_raw.txt; fi", wordlist, wordlist), "default", []string{"httpx_probe"}},

		// 200-only verification of ffuf hits. ffuf above accepts 200/301/302/403
		// for discovery coverage, but downstream scanners (sqlmap, dalfox, etc.)
		// only test endpoints that actually respond 200 — verifying here keeps
		// the dashboard's ffuf_dirs_200.txt count trustworthy.
		{"dirbrute_verify_200", "if [ -s ffuf_dirs_raw.txt ]; then httpx -l ffuf_dirs_raw.txt -silent -status-code -mc 200 -o ffuf_dirs_200.txt; else : > ffuf_dirs_200.txt; fi", "grep", []string{"dirbrute_ffuf"}},
		{"manual_review_queue", "grep -Ei \"checkout|price|payment|coupon|book|cart|fare\" all_urls.txt | sort -u > manual_business_logic_review.txt", "grep", []string{"merge_all_urls"}},

		// === Modern methodology additions (bb-methodology + security-arsenal) ===
		// Each new stage is gated on its tool being present on PATH, so a
		// missing binary skips cleanly instead of failing the pipeline.

		// WAF fingerprinting — know what you're dealing with before tuning
		// payloads. Output is plain text, one WAF vendor per detected host.
		{"waf_detect", "if command -v wafw00f >/dev/null 2>&1; then wafw00f -i alive.txt -o waf_detections.txt || true; else : > waf_detections.txt; fi", "grep", []string{"httpx_probe"}},

		// Port scan (top-1000) on the live host set. We cap rate and top
		// ports so this stays fast even on large subdomain sets.
		{"port_scan_naabu", "if command -v naabu >/dev/null 2>&1; then naabu -list alive.txt -top-ports 1000 -rate 1000 -silent -o naabu_ports.txt || true; else : > naabu_ports.txt; fi", "grep", []string{"httpx_probe"}},

		// Hidden parameter discovery (arjun). Cheap POST/GET brute over
		// a built-in param wordlist — surfaces undocumented query params
		// that the developer never documented and probably never secured.
		// Skipped gracefully when arjun isn't installed.
		{"hidden_params_arjun", "if command -v arjun >/dev/null 2>&1; then mkdir -p arjun_results; while read -r host; do safe_name=$(echo \"$host\" | sed 's|https\\?://||; s|[/:]|_|g'); arjun -u \"$host\" -oT arjun_results/${safe_name}.txt -t 5 2>/dev/null || true; done < alive.txt; cat arjun_results/*.txt 2>/dev/null | sort -u > hidden_params.txt; else : > hidden_params.txt; fi", "grep", []string{"httpx_probe"}},

		// Modern blind SQLi. Methodology prefers ghauri over sqlmap for
		// ID-like parameters; sqlmap still runs in the batch stage
		// above for broad coverage. We only run ghauri against a
		// capped target list (sqlmap would have already chewed
		// through the noisy hits).
		{"ghauri_sqli", "if command -v ghauri >/dev/null 2>&1; then { head -n 200 sqli_targets.txt; grep -Ei '[?&](id|uid|order|product|category|page|article|comment|msg)=' sqli_targets.txt; } | sort -u | head -n 100 > ghauri_targets.txt; [ -s ghauri_targets.txt ] && ghauri -m ghauri_targets.txt --batch --level=2 --risk=1 --technique=BT -o ghauri_results.txt || true; else : > ghauri_results.txt; fi", "grep", []string{"sqli_targets"}},
	}
}

func Run(domain string, resume bool, paths *config.Paths, stepTimeout time.Duration) error {
	cp, err := checkpoint.Load(paths.WorkDir, domain)
	if err != nil {
		return err
	}

	startTime := cp.StartedAt
	if !resume && len(cp.CompletedSteps) > 0 {
		if err := cp.Reset(); err != nil {
			return fmt.Errorf("failed to reset checkpoint: %w", err)
		}
	}

	logFile, err := executor.GetLogFile(paths.WorkDir)
	if err != nil {
		return err
	}
	defer logFile.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n[!] Received interrupt signal. Cleaning up and exiting...")
		cancel()
	}()

	steps := GetSteps(domain, paths)
	stepMap := make(map[string]Step)
	for _, s := range steps {
		stepMap[s.ID] = s
	}

	stepIDs := make([]string, len(steps))
	for i, s := range steps {
		stepIDs[i] = s.ID
	}

	completed := make(map[string]bool)
	running := make(map[string]bool)
	var mu sync.Mutex

	// Max concurrent steps
	maxConcurrent := 5
	semaphore := make(chan struct{}, maxConcurrent)

	for _, s := range steps {
		if cp.IsCompleted(s.ID) {
			completed[s.ID] = true
		}
	}

	// Enter alt-screen + hide cursor before any renderer writes. Pair
	// with StopDashboard on every exit path (normal, error, signal) so
	// we never leave the user's terminal broken. Done explicitly here
	// rather than in a defer because the defer would race with the
	// signal-driven cancel path below.
	cli.StartDashboard()
	defer cli.StopDashboard()

	// Wire the executor's throttled log lines into the cli log panel.
	// Per memory: log-throttling kills the "duplicate frame / scroll
	// flood" bug — full bytes still go to the log file; only every Nth
	// line reaches the dashboard's log panel.
	executor.LineCallback = cli.PushLogLine
	executor.ResetLogThrottle()
	defer func() { executor.LineCallback = nil }()

	fmt.Print("\033[2J\033[H")

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	go func() {
		for {
			select {
			case <-ticker.C:
				uiLock.Lock()
				stats := cli.UpdateStats(paths.WorkDir)
				mu.Lock()
				var activeSteps []string
				for id, isRunning := range running {
					if isRunning {
						activeSteps = append(activeSteps, id)
					}
				}
				cli.DrawDashboard(domain, startTime, stepIDs, completed, strings.Join(activeSteps, ", "), stats)
				mu.Unlock()
				uiLock.Unlock()
			case <-ctx.Done():
				return
			}
		}
	}()

	var wg sync.WaitGroup
	errChan := make(chan error, len(steps))
	stopAndWait := func(err error) error {
		cancel()
		wg.Wait()
		return err
	}

	for {
		mu.Lock()
		if len(completed) == len(steps) {
			mu.Unlock()
			break
		}

		startedAny := false
		for _, s := range steps {
			if completed[s.ID] || running[s.ID] {
				continue
			}

			depsMet := true
			for _, dep := range s.Deps {
				if !completed[dep] {
					depsMet = false
					break
				}
			}

			if depsMet {
				if s.ID == "dirbrute_ffuf" && paths.SeclistsDirWordlist == "" && paths.SeclistsDirWordlistSmall == "" {
					completed[s.ID] = true
					cp.CompleteStep(s.ID)
					continue
				}

				running[s.ID] = true
				startedAny = true
				wg.Add(1)
				go func(step Step) {
					defer wg.Done()
					select {
					case semaphore <- struct{}{}:
					case <-ctx.Done():
						return
					}
					defer func() { <-semaphore }()

					res, err := executor.RunCommand(ctx, step.Command, paths.WorkDir, logFile, stepTimeout)

					mu.Lock()
					delete(running, step.ID)
					if err != nil {
						mu.Unlock()
						if !strings.Contains(err.Error(), "interrupted") {
							errChan <- fmt.Errorf("step %s failed: %v", step.ID, err)
						}
						return
					}

					success := false
					if step.Type == "grep" {
						if res.ExitCode == 0 || res.ExitCode == 1 {
							success = true
						}
					} else {
						if res.ExitCode == 0 {
							success = true
						}
					}

					if !success {
						mu.Unlock()
						errChan <- fmt.Errorf("step %s failed with exit code %d", step.ID, res.ExitCode)
						return
					}

					completed[step.ID] = true
					cp.CompleteStep(step.ID)
					mu.Unlock()
				}(s)
			}
		}
		mu.Unlock()

		if !startedAny {
			select {
			case err := <-errChan:
				return stopAndWait(err)
			case <-ctx.Done():
				return stopAndWait(nil)
			case <-time.After(100 * time.Millisecond):
				continue
			}
		}

		select {
		case err := <-errChan:
			return stopAndWait(err)
		case <-ctx.Done():
			return stopAndWait(nil)
		default:
			time.Sleep(100 * time.Millisecond)
		}
	}

	wg.Wait()

	uiLock.Lock()
	stats := cli.UpdateStats(paths.WorkDir)
	cli.DrawDashboard(domain, startTime, stepIDs, completed, "FINISHED", stats)
	uiLock.Unlock()

	if err := summary.Generate(paths.WorkDir, cp); err != nil {
		return err
	}

	// Leave alt-screen BEFORE the final summary banner so the user sees
	// their real shell prompt on success — alt-screen would mask it.
	cli.StopDashboard()
	executor.LineCallback = nil

	fmt.Printf("\n[+] Pipeline complete! Output saved to %s\n", paths.WorkDir)
	return nil
}
