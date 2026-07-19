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
		{"katana_crawl", "katana -list alive.txt -jc -kf all -d 3 -fs rdn -o katana_urls.txt", "default"},
		{"clean_urls", fmt.Sprintf("grep -Ei '^https?://([a-zA-Z0-9-]+\\.)*%s' katana_urls.txt | grep -Ev '\\.(css|js|png|jpg|jpeg|gif|pdf|svg|ico)($|\\?)' | sed 's/\\\\$//' | sort -u > clean_katana_urls.txt", domainEscaped), "grep"},
		{"trufflehog_scan", "trufflehog filesystem clean_katana_urls.txt --only-verified > trufflehog_results.txt", "default"},
		{"grep_secrets", "grep -Ei \"api_key|apikey|secret|token|password|aws_key|bearer\" clean_katana_urls.txt | sort -u > potential_secrets.txt", "grep"},
		{"sqli_targets", "gf sqli clean_katana_urls.txt > sqli_targets.txt; grep -Ei \"id=|select|report|search|query|sort|category|item|view\" clean_katana_urls.txt >> sqli_targets.txt; sort -u sqli_targets.txt -o sqli_targets.txt", "grep"},
		{"sqlmap_scan", "sqlmap -m sqli_targets.txt --batch --random-agent --level=2 --risk=2 --output-dir=./sqlmap_results", "default"},
		{"xss_targets", "gf xss clean_katana_urls.txt > xss_targets.txt; grep -Ei \"q=|search|query|keyword|text|name|email|msg|redirect|url=\" clean_katana_urls.txt >> xss_targets.txt; sort -u xss_targets.txt -o xss_targets.txt", "grep"},
		{"xss_scan", "cat xss_targets.txt | Gxss -p khXSS | dalfox pipe --output xss_vulnerabilities.txt", "default"},
		{"rce_targets", "gf rce clean_katana_urls.txt > rce_targets.txt; grep -Ei \"cmd=|exec|command|run|ping|ip|file|path|dir|url|daemon|upload\" clean_katana_urls.txt >> rce_targets.txt; sort -u rce_targets.txt -o rce_targets.txt", "grep"},
		{"rce_scan", fmt.Sprintf("nuclei -l rce_targets.txt -t %[1]s/http/vulnerabilities/ -t %[1]s/http/cves/ -severity high,critical -o nuclei_rce_rce.txt", paths.NucleiTemplates), "default"},
		{"idor_targets", "gf idor clean_katana_urls.txt > idor_targets.txt; grep -Ei \"id=|user|account|number|order|doc|file|profile\" clean_katana_urls.txt >> idor_targets.txt; sort -u idor_targets.txt -o idor_targets.txt", "grep"},
		{"idor_scan", fmt.Sprintf("nuclei -l idor_targets.txt -t %[1]s/http/misconfiguration/ -t %[1]s/http/exposed-panels/ -o idor_vulnerabilities.txt", paths.NucleiTemplates), "default"},
	}
}

func Run(domain string, resume bool, paths *config.Paths) error {
	cp, err := checkpoint.Load(paths.WorkDir, domain)
	if err != nil {
		return err
	}

	if !resume && len(cp.CompletedSteps) > 0 {
		// In non-interactive mode ( Manus sandbox), we default to resume if not specified
		// or we could prompt. But spec says default to resume if no TTY.
		fmt.Printf("[!] Existing scan found for %s. Resuming...\n", domain)
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
