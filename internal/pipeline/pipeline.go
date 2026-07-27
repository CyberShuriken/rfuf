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

type Step struct {
	ID      string
	Command string
	Type    string // "default", "grep"
	Deps    []string
}

var (
	uiLock sync.Mutex

	// nucleiOptimized provides better performance for large scans
	nucleiOptimized = "-rl 300 -c 50 -bs 25 -timeout 7 -silent -no-interact"

	// maxScanTargets caps gf/grep output
	maxScanTargets = 5000
)

func GetSteps(domain string, paths *config.Paths) []Step {
	domainEscaped := strings.ReplaceAll(domain, ".", "\\.")

	return []Step{
		{"setup_directories", fmt.Sprintf("mkdir -p %s", paths.WorkDir), "default", nil},
		{"subfinder", fmt.Sprintf("subfinder -d %s -all -o subfinder.txt", domain), "default", []string{"setup_directories"}},
		{"assetfinder", fmt.Sprintf("assetfinder --subs-only %s > assetfinder.txt", domain), "default", []string{"setup_directories"}},
		{"amass_enum", fmt.Sprintf("amass enum -d %s -o amass_raw.txt", domain), "default", []string{"setup_directories"}},
		{"amass_parse", fmt.Sprintf("awk '{print $1}' amass_raw.txt | grep \"%s\" | sort -u > amass_sub.txt", domain), "grep", []string{"amass_enum"}},
		{"merge_subs", "cat subfinder.txt assetfinder.txt amass_sub.txt | sort -u > subs.txt", "default", []string{"subfinder", "assetfinder", "amass_parse"}},
		{"dnsx_resolve", "dnsx -l subs.txt -silent -o live_subs.txt", "default", []string{"merge_subs"}},
		{"subzy_takeover", "subzy run --targets live_subs.txt --vuln | tee subzy_vulnerable.txt", "default", []string{"dnsx_resolve"}},
		{"extract_takeover_targets", fmt.Sprintf("grep \"VULNERABLE\" subzy_vulnerable.txt | grep -oE '[a-zA-Z0-9._-]+\\.%s' | sort -u > takeover_targets.txt", domainEscaped), "grep", []string{"subzy_takeover"}},
			{"validate_takeovers", fmt.Sprintf("nuclei -l takeover_targets.txt -t %s/http/takeovers/ %s -o validated_takeovers.txt", paths.NucleiTemplates, nucleiOptimized), "default", []string{"extract_takeover_targets"}},
			{"httpx_probe", "httpx -l live_subs.txt -silent -o alive.txt", "default", []string{"dnsx_resolve"}},
			{"nuclei_exposures", fmt.Sprintf("nuclei -l alive.txt -tags token-spray,exposure,config -severity medium,high,critical %s -o credentials_found.txt", nucleiOptimized), "default", []string{"httpx_probe"}},
			{"nuclei_misconfigs", fmt.Sprintf("nuclei -l alive.txt -t %[1]s/http/vulnerabilities/ -t %[1]s/http/exposed-panels/ -t %[1]s/http/misconfiguration/ %[2]s -o misconfigs.txt", paths.NucleiTemplates, nucleiOptimized), "default", []string{"httpx_probe"}},
			{"nuclei_auth_scan", fmt.Sprintf("nuclei -l alive.txt -tags jwt,auth-bypass,default-login %s -o auth_results.txt", nucleiOptimized), "default", []string{"httpx_probe"}},
			{"nuclei_graphql_scan", fmt.Sprintf("nuclei -l alive.txt -t %s/http/exposed-panels/graphql/ %s -o graphql_exposed.txt", paths.NucleiTemplates, nucleiOptimized), "default", []string{"httpx_probe"}},
		{"katana_crawl", "katana -list alive.txt -jc -kf all -d 3 -fs rdn -o katana_urls.txt", "default", []string{"httpx_probe"}},
		{"clean_urls", fmt.Sprintf("grep -Ei '^https?://([a-zA-Z0-9-]+\\.)*%s' katana_urls.txt | grep -Ev '\\.(css|js|png|jpg|jpeg|gif|pdf|svg|ico)($|\\?)' | sed 's/\\\\$//' | sort -u > clean_katana_urls.txt", domainEscaped), "grep", []string{"katana_crawl"}},
		{"trufflehog_scan", "trufflehog filesystem clean_katana_urls.txt --only-verified > trufflehog_results.txt", "default", []string{"clean_urls"}},
		{"grep_secrets", "grep -Ei \"api_key|apikey|secret|token|password|aws_key|bearer\" clean_katana_urls.txt | sort -u > potential_secrets.txt", "grep", []string{"clean_urls"}},
		{"gau_urls", "cat live_subs.txt | gau --threads 5 --subs | tee gau_urls.txt", "default", []string{"dnsx_resolve"}},
		{"wayback_urls", "cat live_subs.txt | waybackurls | tee wayback_urls.txt", "default", []string{"dnsx_resolve"}},
		{"merge_all_urls", "cat gau_urls.txt wayback_urls.txt clean_katana_urls.txt | sort -u > all_urls.txt", "default", []string{"gau_urls", "wayback_urls", "clean_urls"}},
		{"sqli_targets", "gf sqli all_urls.txt > sqli_targets.txt; grep -Ei \"id=|select|report|search|query|sort|category|item|view\" all_urls.txt >> sqli_targets.txt; sort -u sqli_targets.txt -o sqli_targets.txt", "grep", []string{"merge_all_urls"}},
		{"sqlmap_scan", "sqlmap -m sqli_targets.txt --batch --random-agent --level=2 --risk=2 --output-dir=./sqlmap_results", "default", []string{"sqli_targets"}},
		{"xss_targets", "gf xss all_urls.txt > xss_targets.txt; grep -Ei \"q=|search|query|keyword|text|name|email|msg|redirect|url=\" all_urls.txt >> xss_targets.txt; sort -u xss_targets.txt -o xss_targets.txt", "grep", []string{"merge_all_urls"}},
		{"xss_scan", "cat xss_targets.txt | Gxss -p khXSS | dalfox pipe --batch --output xss_vulnerabilities.txt", "default", []string{"xss_targets"}},
		{"rce_targets", fmt.Sprintf("{ gf rce all_urls.txt; grep -Ei '[?&](cmd|exec|command|ping|daemon|upload|shell|code)=' all_urls.txt; } | sort -u | head -n %d > rce_targets.txt", maxScanTargets), "grep", []string{"merge_all_urls"}},
		{"rce_scan", fmt.Sprintf("nuclei -l rce_targets.txt -tags rce -severity high,critical %s -o nuclei_rce_rce.txt", nucleiOptimized), "default", []string{"rce_targets"}},
		{"idor_targets", fmt.Sprintf("{ gf idor all_urls.txt; grep -Ei '[?&](id|account|order|doc|profile|booking|reservation|uid|user_id)=' all_urls.txt; } | sort -u | head -n %d > idor_targets.txt", maxScanTargets), "grep", []string{"merge_all_urls"}},
		{"idor_scan", fmt.Sprintf("nuclei -l idor_targets.txt -tags idor %s -o idor_vulnerabilities.txt", nucleiOptimized), "default", []string{"idor_targets"}},
		{"ssrf_targets", "gf ssrf all_urls.txt > ssrf_targets.txt; grep -Ei \"url=|uri=|path=|dest=|redirect=|callback=|webhook=|src=|fetch=|proxy=|target=\" all_urls.txt >> ssrf_targets.txt; sort -u ssrf_targets.txt -o ssrf_targets.txt", "grep", []string{"merge_all_urls"}},
		{"ssrf_scan", fmt.Sprintf("nuclei -l ssrf_targets.txt -tags ssrf %s -o ssrf_vulnerabilities.txt", nucleiOptimized), "default", []string{"ssrf_targets"}},
		{"redirect_targets", fmt.Sprintf("gf redirect all_urls.txt | sort -u | head -n %d > redirect_targets.txt", maxScanTargets), "grep", []string{"merge_all_urls"}},
		{"redirect_scan", fmt.Sprintf("nuclei -l redirect_targets.txt -tags redirect %s -o open_redirect_results.txt", nucleiOptimized), "default", []string{"redirect_targets"}},
		{"lfi_targets", "gf lfi all_urls.txt > lfi_targets.txt; sort -u lfi_targets.txt -o lfi_targets.txt", "grep", []string{"merge_all_urls"}},
		{"lfi_scan", fmt.Sprintf("nuclei -l lfi_targets.txt -tags lfi %s -o lfi_results.txt", nucleiOptimized), "default", []string{"lfi_targets"}},
		{"cors_check", "while read -r url; do curl -s -H \"Origin: https://evil.com\" -I \"$url\" | grep -qi \"access-control-allow-origin: https://evil.com\" && echo \"[VULN] $url\"; done < alive.txt > cors_findings.txt", "grep", []string{"httpx_probe"}},
		{"dirbrute_ffuf", fmt.Sprintf("mkdir -p ffuf_results; while read -r host; do safe_name=$(echo \"$host\" | sed 's|https\\?://||; s|[/:]|_|g'); ffuf -w %s -u \"${host}/FUZZ\" -mc 200 -o \"ffuf_results/${safe_name}.json\" -of json -s; done < alive.txt; for f in ffuf_results/*.json; do jq -r '.results[]? | .url' \"$f\" 2>/dev/null; done | sort -u > ffuf_dirs_200.txt", paths.SeclistsDirWordlist), "default", []string{"httpx_probe"}},
		{"manual_review_queue", "grep -Ei \"checkout|price|payment|coupon|book|cart|fare\" all_urls.txt | sort -u > manual_business_logic_review.txt", "grep", []string{"merge_all_urls"}},
	}
}

func Run(domain string, resume bool, paths *config.Paths) error {
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
					if s.ID == "dirbrute_ffuf" && paths.SeclistsDirWordlist == "" {
						completed[s.ID] = true
						cp.CompleteStep(s.ID)
						continue
					}
	
					running[s.ID] = true
					startedAny = true
					wg.Add(1)
					go func(step Step) {
						defer wg.Done()
						semaphore <- struct{}{}
						defer func() { <-semaphore }()

						res, err := executor.RunCommand(step.Command, paths.WorkDir, logFile)
						
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
				return err
			case <-ctx.Done():
				return nil
			case <-time.After(100 * time.Millisecond):
				continue
			}
		}

		select {
		case err := <-errChan:
			return err
		case <-ctx.Done():
			return nil
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

	fmt.Printf("\n[+] Pipeline complete! Output saved to %s\n", paths.WorkDir)
	return nil
}
