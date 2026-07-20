package pipeline

import (
	"fmt"
	"strings"

	"github.com/CyberShuriken/rfuf/internal/checkpoint"
	"github.com/CyberShuriken/rfuf/internal/config"
	"github.com/CyberShuriken/rfuf/internal/executor"
	"github.com/CyberShuriken/rfuf/internal/summary"
)

type Step struct {
	ID      string
	Command string
	Type    string // "default", "grep"
}

func GetSteps(domain string, paths *config.Paths) []Step {
	domainEscaped := strings.ReplaceAll(domain, ".", "\\.")

	return []Step{
		{"setup_directories", fmt.Sprintf("mkdir -p %s", paths.WorkDir), "default"},
		{"subfinder", fmt.Sprintf("subfinder -d %s -all -o subfinder.txt", domain), "default"},
		{"assetfinder", fmt.Sprintf("assetfinder --subs-only %s > assetfinder.txt", domain), "default"},
		{"amass_enum", fmt.Sprintf("amass enum -d %s -o amass_raw.txt", domain), "default"},
		{"amass_parse", fmt.Sprintf("awk '{print $1}' amass_raw.txt | grep \"%s\" | sort -u > amass_sub.txt", domain), "grep"},
		{"merge_subs", "cat subfinder.txt assetfinder.txt amass_sub.txt | sort -u > subs.txt", "default"},
		{"dnsx_resolve", "dnsx -l subs.txt -silent -o live_subs.txt", "default"},
		{"subzy_takeover", "subzy run --targets live_subs.txt --vuln | tee subzy_vulnerable.txt", "default"},
		{"extract_takeover_targets", fmt.Sprintf("grep \"VULNERABLE\" subzy_vulnerable.txt | grep -oE '[a-zA-Z0-9._-]+\\.%s' | sort -u > takeover_targets.txt", domainEscaped), "grep"},
		{"validate_takeovers", fmt.Sprintf("nuclei -l takeover_targets.txt -t %s/http/takeovers/ -o validated_takeovers.txt", paths.NucleiTemplates), "default"},
		{"httpx_probe", "httpx -l live_subs.txt -silent -o alive.txt", "default"},
		{"nuclei_exposures", "nuclei -l alive.txt -tags token-spray,exposure,config -severity medium,high,critical -o credentials_found.txt", "default"},
		{"nuclei_misconfigs", fmt.Sprintf("nuclei -l alive.txt -t %[1]s/http/vulnerabilities/ -t %[1]s/http/exposed-panels/ -t %[1]s/http/misconfiguration/ -o misconfigs.txt", paths.NucleiTemplates), "default"},
		{"nuclei_auth_scan", "nuclei -l alive.txt -tags jwt,auth-bypass,default-login -o auth_results.txt", "default"},
		{"nuclei_graphql_scan", fmt.Sprintf("nuclei -l alive.txt -t %s/http/exposed-panels/graphql/ -o graphql_exposed.txt", paths.NucleiTemplates), "default"},
		{"katana_crawl", "katana -list alive.txt -jc -kf all -d 3 -fs rdn -o katana_urls.txt", "default"},
		{"clean_urls", fmt.Sprintf("grep -Ei '^https?://([a-zA-Z0-9-]+\\.)*%s' katana_urls.txt | grep -Ev '\\.(css|js|png|jpg|jpeg|gif|pdf|svg|ico)($|\\?)' | sed 's/\\\\$//' | sort -u > clean_katana_urls.txt", domainEscaped), "grep"},
		{"trufflehog_scan", "trufflehog filesystem clean_katana_urls.txt --only-verified > trufflehog_results.txt", "default"},
		{"grep_secrets", "grep -Ei \"api_key|apikey|secret|token|password|aws_key|bearer\" clean_katana_urls.txt | sort -u > potential_secrets.txt", "grep"},
		{"gau_urls", "cat live_subs.txt | gau --threads 5 --subs | tee gau_urls.txt", "default"},
		{"wayback_urls", "cat live_subs.txt | waybackurls | tee wayback_urls.txt", "default"},
		{"merge_all_urls", "cat gau_urls.txt wayback_urls.txt clean_katana_urls.txt | sort -u > all_urls.txt", "default"},
		{"sqli_targets", "gf sqli all_urls.txt > sqli_targets.txt; grep -Ei \"id=|select|report|search|query|sort|category|item|view\" all_urls.txt >> sqli_targets.txt; sort -u sqli_targets.txt -o sqli_targets.txt", "grep"},
		{"sqlmap_scan", "sqlmap -m sqli_targets.txt --batch --random-agent --level=2 --risk=2 --output-dir=./sqlmap_results", "default"},
		{"xss_targets", "gf xss all_urls.txt > xss_targets.txt; grep -Ei \"q=|search|query|keyword|text|name|email|msg|redirect|url=\" all_urls.txt >> xss_targets.txt; sort -u xss_targets.txt -o xss_targets.txt", "grep"},
		{"xss_scan", "cat xss_targets.txt | Gxss -p khXSS | dalfox pipe --output xss_vulnerabilities.txt", "default"},
		{"rce_targets", "gf rce all_urls.txt > rce_targets.txt; grep -Ei \"cmd=|exec|command|run|ping|ip|file|path|dir|url|daemon|upload\" all_urls.txt >> rce_targets.txt; sort -u rce_targets.txt -o rce_targets.txt", "grep"},
		{"rce_scan", fmt.Sprintf("nuclei -l rce_targets.txt -t %[1]s/http/vulnerabilities/ -t %[1]s/http/cves/ -severity high,critical -o nuclei_rce_rce.txt", paths.NucleiTemplates), "default"},
		{"idor_targets", "gf idor all_urls.txt > idor_targets.txt; grep -Ei \"id=|user|account|number|order|doc|file|profile|booking|reservation\" all_urls.txt >> idor_targets.txt; sort -u idor_targets.txt -o idor_targets.txt", "grep"},
		{"idor_scan", fmt.Sprintf("nuclei -l idor_targets.txt -t %[1]s/http/misconfiguration/ -t %[1]s/http/exposed-panels/ -o idor_vulnerabilities.txt", paths.NucleiTemplates), "default"},
		{"ssrf_targets", "gf ssrf all_urls.txt > ssrf_targets.txt; grep -Ei \"url=|uri=|path=|dest=|redirect=|callback=|webhook=|src=|fetch=|proxy=|target=\" all_urls.txt >> ssrf_targets.txt; sort -u ssrf_targets.txt -o ssrf_targets.txt", "grep"},
		{"ssrf_scan", "nuclei -l ssrf_targets.txt -tags ssrf -o ssrf_vulnerabilities.txt", "default"},
		{"redirect_targets", "gf redirect all_urls.txt > redirect_targets.txt; sort -u redirect_targets.txt -o redirect_targets.txt", "grep"},
		{"redirect_scan", "nuclei -l redirect_targets.txt -tags redirect -o open_redirect_results.txt", "default"},
		{"lfi_targets", "gf lfi all_urls.txt > lfi_targets.txt; sort -u lfi_targets.txt -o lfi_targets.txt", "grep"},
		{"lfi_scan", "nuclei -l lfi_targets.txt -tags lfi -o lfi_results.txt", "default"},
		{"cors_check", "while read -r url; do curl -s -H \"Origin: https://evil.com\" -I \"$url\" | grep -qi \"access-control-allow-origin: https://evil.com\" && echo \"[VULN] $url\"; done < alive.txt > cors_findings.txt", "grep"},
		{"dirbrute_ffuf", fmt.Sprintf("mkdir -p ffuf_results; while read -r host; do safe_name=$(echo \"$host\" | sed 's|https\\?://||; s|[/:]|_|g'); ffuf -w %s -u \"${host}/FUZZ\" -mc 200 -o \"ffuf_results/${safe_name}.json\" -of json -s; done < alive.txt; for f in ffuf_results/*.json; do jq -r '.results[]? | .url' \"$f\" 2>/dev/null; done | sort -u > ffuf_dirs_200.txt", paths.SeclistsDirWordlist), "default"},
		{"manual_review_queue", "grep -Ei \"checkout|price|payment|coupon|book|cart|fare\" all_urls.txt | sort -u > manual_business_logic_review.txt", "grep"},
	}
}

func Run(domain string, resume bool, paths *config.Paths) error {
	cp, err := checkpoint.Load(paths.WorkDir, domain)
	if err != nil {
		return err
	}

	// If the user did not pass -resume but a previous checkpoint exists,
	// treat this as a fresh run: clear the checkpoint so every step
	// re-runs from scratch instead of being silently skipped.
	if !resume && len(cp.CompletedSteps) > 0 {
		fmt.Printf("[!] Existing checkpoint found for %s. Starting fresh scan (use -resume to continue previous run)...\n", domain)
		if err := cp.Reset(); err != nil {
			return fmt.Errorf("failed to reset checkpoint: %w", err)
		}
	}

	logFile, err := executor.GetLogFile(paths.WorkDir)
	if err != nil {
		return err
	}
	defer logFile.Close()

	steps := GetSteps(domain, paths)
	for i, s := range steps {
		if cp.IsCompleted(s.ID) {
			fmt.Printf("[%d/%d] %s — [SKIP] (already completed)\n", i+1, len(steps), s.ID)
			continue
		}

		fmt.Printf("[%d/%d] %s — running...\n", i+1, len(steps), s.ID)

		// Special handling for dirbrute_ffuf if wordlist is missing
		if s.ID == "dirbrute_ffuf" && paths.SeclistsDirWordlist == "" {
			fmt.Printf("[%d/%d] %s — [SKIP] (Seclists wordlist not found)\n", i+1, len(steps), s.ID)
			cp.CompleteStep(s.ID)
			continue
		}

		res, err := executor.RunCommand(s.Command, paths.WorkDir, logFile)
		if err != nil {
			fmt.Printf("[%d/%d] %s — FAILED: %v\n", i+1, len(steps), s.ID, err)
			return err
		}

		success := false
		if s.Type == "grep" {
			if res.ExitCode == 0 || res.ExitCode == 1 {
				success = true
			}
		} else {
			if res.ExitCode == 0 {
				success = true
			}
		}

		if !success {
			fmt.Printf("[%d/%d] %s — FAILED (exit code %d). See .rfuf/rfuf.log\n", i+1, len(steps), s.ID, res.ExitCode)
			return fmt.Errorf("step %s failed", s.ID)
		}

		fmt.Printf("[%d/%d] %s — done (%v)\n", i+1, len(steps), s.ID, res.Duration)
		cp.CompleteStep(s.ID)
	}

	fmt.Println("[*] Generating summary...")
	if err := summary.Generate(paths.WorkDir, cp); err != nil {
		return err
	}

	fmt.Printf("[+] Pipeline complete! Output saved to %s\n", paths.WorkDir)
	return nil
}
