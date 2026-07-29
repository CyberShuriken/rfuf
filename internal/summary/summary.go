package summary

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CyberShuriken/rfuf/internal/checkpoint"
)

// Generate builds SUMMARY.md (top-level counts) and findings.md (the
// per-finding, severity-grouped read-for-hunting report). The hunter
// opens findings.md first — it lists every URL that needs a manual retest,
// grouped by severity, with a "what to do next" hint per category.
// SUMMARY.md is the at-a-glance rollup for quick triage.
func Generate(workDir string, cp *checkpoint.Checkpoint) error {
	duration := cp.LastUpdated.Sub(cp.StartedAt)

	// Recon stats.
	subdomains := countLines(filepath.Join(workDir, "subs.txt"))
	liveSubs := countLines(filepath.Join(workDir, "live_subs.txt"))
	aliveHosts := countLines(filepath.Join(workDir, "alive.txt"))

	// Vulnerability data.
	takeovers := getFileContent(filepath.Join(workDir, "validated_takeovers.txt"))
	secrets := getFileContent(filepath.Join(workDir, "trufflehog_results.txt"))
	potentialSecrets := getFileContent(filepath.Join(workDir, "potential_secrets.txt"))
	auth := getFileContent(filepath.Join(workDir, "auth_results.txt"))
	graphql := getFileContent(filepath.Join(workDir, "graphql_exposed.txt"))
	ssrf := getFileContent(filepath.Join(workDir, "ssrf_vulnerabilities.txt"))
	redirect := getFileContent(filepath.Join(workDir, "open_redirect_results.txt"))
	lfi := getFileContent(filepath.Join(workDir, "lfi_results.txt"))
	cors := getFileContent(filepath.Join(workDir, "cors_findings.txt"))
	xss := getFileContent(filepath.Join(workDir, "xss_vulnerabilities.txt"))
	rce := getFileContent(filepath.Join(workDir, "nuclei_rce_rce.txt"))
	idor := getFileContent(filepath.Join(workDir, "idor_vulnerabilities.txt"))
	ffuf := getFileContent(filepath.Join(workDir, "ffuf_dirs_200.txt"))
	waf := getFileContent(filepath.Join(workDir, "waf_detections.txt"))
	ports := getFileContent(filepath.Join(workDir, "naabu_ports.txt"))
	hiddenParams := getFileContent(filepath.Join(workDir, "hidden_params.txt"))
	ghauri := getFileContent(filepath.Join(workDir, "ghauri_results.txt"))

	// SQLi is filtered through a confidence gate so the dashboard's
	// SQLi count reflects only payload-confirmed folders — not the
	// "Parameter appears to be injectable" header that sqlmap writes
	// on every false-positive timeout.
	sqlmapConfirmed, sqlmapDropped := confirmedSqlmapResults(filepath.Join(workDir, "sqlmap_results"))

	// === findings.md — the report the hunter reads ===
	findings := buildFindingsReport(cp, duration, FindingsBuckets{
		RCE:             rce,
		Takeovers:       takeovers,
		LFI:             lfi,
		SSRF:            ssrf,
		Secrets:         secrets,
		XSS:             xss,
		Auth:            auth,
		IDOR:            idor,
		Redirect:        redirect,
		SQLi:            sqlmapConfirmed,
		GraphQL:         graphql,
		CORS:            cors,
		WAF:             waf,
		Ports:           ports,
		HiddenParams:    hiddenParams,
		Ghauri:          ghauri,
		PotentialSecrets: potentialSecrets,
		FFUF:            ffuf,
		ManualReview:    getFileContent(filepath.Join(workDir, "manual_business_logic_review.txt")),

		// Filtered-out appendix.
		DroppedSQLiCandidates: sqlmapDropped,
		DroppedURLTotal:       countLines(filepath.Join(workDir, "all_urls.txt")) - countLines(filepath.Join(workDir, "all_urls_200.txt")),
	})

	if err := os.WriteFile(filepath.Join(workDir, "findings.md"), []byte(findings), 0644); err != nil {
		return err
	}

	// === SUMMARY.md — at-a-glance counts ===
	summary := fmt.Sprintf(`# RFUF Scan Summary for %s

- **Scan Started:** %s
- **Scan Finished:** %s
- **Total Duration:** %v

## Recon Stats
- **Total Subdomains:** %d
- **Live Subdomains (DNS):** %d
- **Alive HTTP Hosts:** %d

## Vulnerability Overview
- **RCE:** %d
- **Takeovers:** %d
- **LFI:** %d
- **SSRF:** %d
- **XSS:** %d
- **SQLi (sqlmap, confirmed only):** %d   *(raw candidate folders: %d)*
- **SQLi (ghauri, modern blind):** %d
- **Secrets:** %d
- **Auth/JWT:** %d
- **CORS:** %d
- **FFUF (200-only verified):** %d
- **WAF Detections:** %d
- **Open Ports:** %d
- **Hidden Params:** %d

## Detailed report
Open [findings.md](./findings.md) — every URL to retest, grouped by
severity, with false-positive filtering transparent.
`, cp.Domain, cp.StartedAt.Format(time.RFC822), cp.LastUpdated.Format(time.RFC822), duration,
		subdomains, liveSubs, aliveHosts,
		len(rce), len(takeovers), len(lfi), len(ssrf), len(xss),
		len(sqlmapConfirmed), countFolders(filepath.Join(workDir, "sqlmap_results")),
		len(ghauri),
		len(secrets)+len(potentialSecrets), len(auth), len(cors), len(ffuf),
		len(waf), len(ports), len(hiddenParams))

	return os.WriteFile(filepath.Join(workDir, "SUMMARY.md"), []byte(summary), 0644)
}

// FindingsBuckets holds every per-category finding slice so the report
// builder can iterate without an explosion of positional string args.
type FindingsBuckets struct {
	RCE             []string
	Takeovers       []string
	LFI             []string
	SSRF            []string
	Secrets         []string
	XSS             []string
	Auth            []string
	IDOR            []string
	Redirect        []string
	SQLi            []string
	GraphQL         []string
	CORS            []string
	WAF             []string
	Ports           []string
	HiddenParams    []string
	Ghauri          []string
	PotentialSecrets []string
	FFUF            []string
	ManualReview    []string

	// Filtered-out appendix.
	DroppedSQLiCandidates []string
	DroppedURLTotal       int
}

// buildFindingsReport returns the full findings.md body. Sections are
// ordered by severity. Each section lists the raw URLs, then a "Recommended
// manual retest" hint the hunter can follow without re-reading tool docs.
func buildFindingsReport(cp *checkpoint.Checkpoint, duration time.Duration, b FindingsBuckets) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# Findings for %s\n\n", cp.Domain))
	sb.WriteString(fmt.Sprintf("Generated: %s    |    Duration: %v\n\n", time.Now().Format(time.RFC822), duration))
	sb.WriteString("> Severity-grouped. Each section lists the raw URLs found and a hint for what to retest manually.\n")
	sb.WriteString("> SQLi counts only payload-confirmed results — see the appendix for what was filtered out and why.\n\n")

	// ─── CRITICAL ────────────────────────────────────────────────────────
	addSection(&sb, "Critical: Remote Code Execution", b.RCE,
		"Potential Remote Code Execution detected by Nuclei templates (CVE-driven).",
		"Open each URL with a debugger proxy. Look for evidence of `system()`, `Runtime.exec`, `ProcessBuilder`, "+
			"`os.popen`, or eval() in the response. If the URL is `?cmd=`, replace with `?cmd=id;echo RFUF` and compare.")

	// ─── HIGH ────────────────────────────────────────────────────────────
	addSection(&sb, "High: Subdomain Takeovers", b.Takeovers,
		"Confirmed subdomain takeovers (subzy + nuclei).",
		"Re-register the dangling service (S3 bucket, GitHub Pages, Azure). "+
			"Test for cookie-bite on the parent domain before reporting — most programs want the parent+sub chain.")

	addSection(&sb, "High: LFI Findings", b.LFI,
		"Potential Local File Inclusion detected by Nuclei.",
		"Append `?file=../../../../etc/passwd` (or `file=..\\..\\..\\..\\windows\\win.ini` on IIS). Pass a known "+
			"unique marker like `RFUFMARKER`, then grep the response for it. Empty response ≠ not vulnerable; check 200 vs 400.")

	addSection(&sb, "High: SSRF Findings", b.SSRF,
		"Potential Server Side Request Forgery detected by Nuclei.",
		"Test the param with `http://169.254.169.254/latest/meta-data/` (AWS), `http://metadata.google.internal` (GCP), "+
			"`http://127.0.0.1:PORT`. If you see a 200 with metadata, escalate to a takeover; otherwise, file as a normal SSRF.")

	addSection(&sb, "High: Verified Secrets", b.Secrets,
		"Secrets verified by TruffleHog (only-verified mode).",
		"DO NOT paste these into a report. Confirm the secret is in scope of the target's bug bounty program, "+
			"then disclose via the platform's secure form. Rotate the credential immediately if you have write access through a test tenant.")

	// ─── MEDIUM ──────────────────────────────────────────────────────────
	addSection(&sb, "Medium: SQLi (payload-confirmed)", b.SQLi,
		"sqlmap confirmed an injectable parameter via at least one technique (boolean, time, union, error, or stacked).",
		"Re-run with `sqlmap -u 'URL' --risk=3 --level=5 --technique=BEUSTQ --dbms=guess` to enumerate the DB. "+
			"Confirm the database name matches the target's stack before reporting. False positives are filtered out — see appendix.")

	addSection(&sb, "Medium: SQLi (ghauri, modern blind)", b.Ghauri,
		"ghauri found a boolean/time-based blind hit. Modern tool — less noisy than batch sqlmap.",
		"Cross-check with manual curl: append `AND 1=1` vs `AND 1=2` and compare response lengths. "+
			"ghauri's UI is approximate; the curl test is the source of truth.")

	addSection(&sb, "Medium: XSS Vulnerabilities", b.XSS,
		"Dalfox-confirmed XSS. Reflected XSS requires a victim to click a crafted link.",
		"Open the URL in a private browser window. Verify the payload executes in the DOM (not just reflected in the source). "+
			"For stored XSS, retest without cookies / via a fresh test account. Filter out cases where the payload is in an unreachable inline JSON.")

	addSection(&sb, "Medium: Auth & JWT Issues", b.Auth,
		"Auth/JWT issues — default logins, signature stripping, `alg:none`, etc.",
		"For each line, open the URL and try: (1) `Authorization: Bearer None`, (2) `alg: none` JWT, (3) `admin:admin` defaults. "+
			"Anything that returns 200 is reportable; anything 401/403 is a misconfig but not exploitable.")

	addSection(&sb, "Medium: IDOR", b.IDOR,
		"Potential Insecure Direct Object Reference detected by Nuclei.",
		"Authenticate as user A, hit the URL. Capture the response. Logout, authenticate as user B, hit the SAME URL. "+
			"If B sees A's data, it's IDOR. Set up a test account in both roles before scanning — without two accounts, you can't confirm.")

	addSection(&sb, "Medium: Open Redirects", b.Redirect,
		"Open redirect — can be chained with OAuth or phishing.",
		"Replace `?url=//attacker.com` and confirm the response is a 30x with `Location: //attacker.com`. "+
			"Open redirects only matter when chained (e.g. as the OAuth `redirect_uri`); a bare open redirect is usually Out-of-Scope on modern programs.")

	// ─── LOW ─────────────────────────────────────────────────────────────
	addSection(&sb, "Low: GraphQL Exposure", b.GraphQL,
		"Exposed GraphQL endpoint found.",
		"Run `graphql-cop` or `graphw00f` against the endpoint. Check for introspection enabled (`__schema` query). "+
			"Introspection + sensitive field names is reportable; introspection alone is Low.")

	addSection(&sb, "Low: CORS Misconfigurations", b.CORS,
		"CORS misconfig that allows cross-origin data access.",
		"Re-curl with `Origin: https://attacker.com` and `Origin: null`. If either is reflected in `Access-Control-Allow-Origin` AND `Allow-Credentials: true`, it's exploitable. "+
			"Otherwise, it's a misconfig but not exploitable in modern browsers.")

	// ─── INFO ────────────────────────────────────────────────────────────
	addSection(&sb, "Info: WAF Detections", b.WAF,
		"WAF vendor fingerprinting — useful for tuning bypass payloads later.",
		"Use the detected WAF to pick payloads: Cloudflare/Cloudfront → use `cloacked` style bypass; AWS WAF → use case-mixed; "+
			"Imperva → use chunked transfer.")

	addSection(&sb, "Info: Exposed Ports", b.Ports,
		"Top-1000 TCP ports exposed on live hosts (from naabu).",
		"Look for unexpected services: 8080/8443 (admin panels), 6379 (Redis), 11211 (Memcached), 9200 (Elasticsearch), "+
			"5601 (Kibana). Each is a follow-up target for a deeper scan.")

	addSection(&sb, "Info: Hidden Parameters", b.HiddenParams,
		"Undocumented query parameters discovered by arjun.",
		"For each new param, test: (1) `?newparam=admin` (vertical priv-esc), (2) `?newparam=../../etc/passwd` (LFI), "+
			"(3) `?newparam=<script>` (XSS). Even a single hit on a hidden param is a reportable bug.")

	addSection(&sb, "Info: Potential Secrets (Grep)", b.PotentialSecrets,
		"URLs containing keywords like `api_key`, `secret`, `token`. Not cracked — pattern matches only.",
		"Open each URL. If the value is a real-looking key, run it through TruffleHog or `gitrob` against the company's GitHub. "+
			"Most are test/example keys. Only report if the key actually authenticates against a live service.")

	addSection(&sb, "Info: Hidden Directories (FFUF, 200-verified)", b.FFUF,
		"Directories found via ffuf, re-checked with httpx to confirm status 200.",
		"Read each — `.git/config`, `.env`, `backup.zip`, `admin.php`, `phpinfo.php` are the top hits. "+
			"For `.git` exposure, run `git-dumper` to clone and grep for secrets. For `.env`, the file contents are usually the report.")

	addSection(&sb, "Info: Manual Review Queue", b.ManualReview,
		"URLs containing checkout/payment/coupon keywords — not auto-scanned, flagged for human review.",
		"Authenticate and walk through each one. Look for: race conditions on coupon application, "+
			"price manipulation on negative-quantity, currency confusion, missing server-side total recalculation.")

	// ─── APPENDIX: WHAT WAS FILTERED OUT ─────────────────────────────────
	sb.WriteString("---\n\n## What was filtered out (false positives removed)\n\n")
	sb.WriteString(fmt.Sprintf("- **URLs pruned for not responding 200:** %d endpoints from gau/wayback/katana "+
		"were dropped before the vuln scanners. They couldn't be tested — only 200-responding endpoints were tested.\n",
		b.DroppedURLTotal))
	sb.WriteString(fmt.Sprintf("- **sqlmap candidate folders dropped (not confirmed):** %d folders were excluded from the SQLi count above. "+
		"A folder is excluded unless its `log` file contains both a real technique id (e.g. `boolean-based blind`) AND a non-empty `Payload:` line. "+
		"sqlite/stub-only/CF-timeout folders fall away here.\n", len(b.DroppedSQLiCandidates)))
	if len(b.DroppedSQLiCandidates) > 0 {
		sb.WriteString("\n<details><summary>Dropped sqlmap candidates (forensic)</summary>\n\n")
		for _, entry := range b.DroppedSQLiCandidates {
			sb.WriteString("- ")
			sb.WriteString(entry)
			sb.WriteString("\n")
		}
		sb.WriteString("\n</details>\n")
	}
	if b.DroppedURLTotal == 0 && len(b.DroppedSQLiCandidates) == 0 {
		sb.WriteString("\n_No candidates were filtered out on this run._\n")
	}
	return sb.String()
}

// addSection appends a single severity-grouped section to sb. Skips
// empty sections so the report doesn't show empty "Critical" sections
// when nothing's critical.
func addSection(sb *strings.Builder, title string, items []string, desc string, retestHint string) {
	if len(items) == 0 {
		return
	}
	sb.WriteString(fmt.Sprintf("## %s (%d)\n\n", title, len(items)))
	sb.WriteString("> ")
	sb.WriteString(desc)
	sb.WriteString("\n\n")
	for _, item := range items {
		sb.WriteString("- ")
		sb.WriteString(item)
		sb.WriteString("\n")
	}
	sb.WriteString("\n**Recommended manual retest:** ")
	sb.WriteString(retestHint)
	sb.WriteString("\n\n")
}

// ConfirmedSqlmapCount returns just the count of confirmed sqlmap
// result folders (those with a real technique id AND a non-empty
// payload). Exposed for the live dashboard so its SQLi stat reflects
// payload-confirmed findings rather than the raw folder count.
func ConfirmedSqlmapCount(root string) int {
	confirmed, _ := confirmedSqlmapResults(root)
	return len(confirmed)
}

// confirmedSqlmapResults walks sqlmap_results/<hostname>/ and splits
// folders into confirmed vs dropped. A folder is "confirmed" if its `log`
// file mentions a real technique id (boolean, time, union, error, or
// stacked) AND a non-empty `Payload:` line. Everything else —
// sqlite-only, CF-timeout stub folders, "might be" headers — is dropped.
func confirmedSqlmapResults(root string) (confirmed []string, dropped []string) {
	entries, err := os.ReadDir(root)
	if err != nil {
		// No sqlmap_results dir at all → no findings, no drops.
		return nil, nil
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		host := e.Name()
		logPath := filepath.Join(root, host, "log")
		logData, err := os.ReadFile(logPath)
		if err != nil {
			// No log file → not a real result folder.
			dropped = append(dropped, host+" (no log file)")
			continue
		}
		text := string(logData)
		if hasRealTechnique(text) && hasPayload(text) {
			confirmed = append(confirmed, host)
		} else {
			dropped = append(dropped, host+" (no real technique + payload)")
		}
	}
	return confirmed, dropped
}

// hasRealTechnique returns true when the log text names a concrete
// technique — not the "might be" warning sqlmap prints on every target.
func hasRealTechnique(text string) bool {
	markers := []string{
		"boolean-based blind",
		"time-based blind",
		"UNION query",
		"stacked queries",
		"error-based",
	}
	for _, m := range markers {
		if strings.Contains(text, m) {
			return true
		}
	}
	return false
}

// hasPayload returns true when the log contains a Payload: line that
// sqlmap writes ONLY after a real technique succeeded. sqlmap's
// "Parameter might be injectable" header has no Payload line.
func hasPayload(text string) bool {
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Payload:") {
			rest := strings.TrimSpace(strings.TrimPrefix(line, "Payload:"))
			if rest != "" {
				return true
			}
		}
	}
	return false
}

func countFolders(path string) int {
	entries, err := os.ReadDir(path)
	if err != nil {
		return 0
	}
	count := 0
	for _, e := range entries {
		if e.IsDir() {
			count++
		}
	}
	return count
}

func getFileContent(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return []string{}
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var result []string
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			result = append(result, line)
		}
	}
	return result
}

func countLines(path string) int {
	return len(getFileContent(path))
}
