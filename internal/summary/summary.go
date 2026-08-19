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

	// === Tech-aware findings (Discourse / Laravel / WordPress / cache poison) ===
	// These come from the new tech_fingerprint-driven stages. Each
	// surface is explicitly targeted at a known stack — generic vuln
	// scanners miss most of these because their templates don't know
	// about forum/framework-specific endpoints.
	discourse := getFileContent(filepath.Join(workDir, "discourse_findings.txt"))
	laravel := getFileContent(filepath.Join(workDir, "laravel_findings.txt"))
	wordpress := getFileContent(filepath.Join(workDir, "wordpress_findings.txt"))
	cachePoison := getFileContent(filepath.Join(workDir, "cache_poison_findings.txt"))

	// === JS bundle artifacts ===
	// Endpoint and key extraction from .js bundles that the crawler
	// couldn't reach via direct links (loaded via JS navigation).
	jsEndpoints := getFileContent(filepath.Join(workDir, "js_endpoints.txt"))

	// === NEW: API discovery + BOLA / Next.js-Plaid-JWT probes ===
	// The two highest-yield additions for SPA / API-heavy targets where
	// katana+gau+wayback return empty scanner target lists.
	apiSpecs := getFileContent(filepath.Join(workDir, "api_specs.txt"))
	bolaTargets := getFileContent(filepath.Join(workDir, "bola_targets.txt"))
	nextjsPlaidJWT := getFileContent(filepath.Join(workDir, "nextjs_plaid_jwt_findings.txt"))
	jsSecrets := getFileContent(filepath.Join(workDir, "js_secrets.txt"))
	jsEndpointFindings := getFileContent(filepath.Join(workDir, "js_endpoint_findings.txt"))

	// === Tech fingerprint rollup ===
	// Per-host stack signal. Used by both the dashboard and the report
	// so the hunter can see which hosts ran which tech-specific probes.
	techFingerprint := getFileContent(filepath.Join(workDir, "tech_fingerprint.txt"))

	// === Phase 1 finder outputs (10 modules wired in pipeline.go) ===
	reflectionFindings := getFileContent(filepath.Join(workDir, "reflection_findings.txt"))
	paramshapeFindings := getFileContent(filepath.Join(workDir, "paramshape_findings.txt"))
	authshapeFindings := getFileContent(filepath.Join(workDir, "authshape_findings.txt"))
	signupTakeoverFindings := getFileContent(filepath.Join(workDir, "signup_takeover_findings.txt"))
	idorSurfaceFindings := getFileContent(filepath.Join(workDir, "idor_surface.txt"))
	oauthFindings := getFileContent(filepath.Join(workDir, "oauth_findings.txt"))
	raceResults := getFileContent(filepath.Join(workDir, "race_results.txt"))
	bucketFindings := getFileContent(filepath.Join(workDir, "bucket_findings.txt"))
	takeoverV2Findings := getFileContent(filepath.Join(workDir, "takeover_v2_findings.txt"))
	jsMineFindings := getFileContent(filepath.Join(workDir, "js_mine_findings.txt"))

	// === Phase 2 new-finder outputs (5 new modules) ===
	secheadersFindings := getFileContent(filepath.Join(workDir, "secheaders_findings.txt"))
	backupscanFindings := getFileContent(filepath.Join(workDir, "backupscan_findings.txt"))
	businesslogicFindings := getFileContent(filepath.Join(workDir, "business_logic_findings.txt"))
	hostheaderFindings := getFileContent(filepath.Join(workDir, "hostheader_findings.txt"))
	cors2Findings := getFileContent(filepath.Join(workDir, "cors2_findings.txt"))

	// === Phase 3 custom nuclei pass ===
	nucleiRfufPass := getFileContent(filepath.Join(workDir, "nuclei_rfuf_pass.txt"))

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
		APISpecs:        apiSpecs,
		BOLATargets:     bolaTargets,
		NextjsPlaidJWT:  nextjsPlaidJWT,

		// Tech-aware findings (Discourse / Laravel / WordPress / cache poison).
		DiscourseFindings:   discourse,
		LaravelFindings:     laravel,
		WordPressFindings:   wordpress,
		CachePoisonFindings: cachePoison,

		// JS bundle artifacts.
		JSEndpoints:        jsEndpoints,
		JSSecrets:          jsSecrets,
		JSEndpointFindings: jsEndpointFindings,

		// Tech fingerprint rollup.
		TechFingerprint: techFingerprint,

		// Filtered-out appendix.
		DroppedSQLiCandidates: sqlmapDropped,
		DroppedURLTotal:       countLines(filepath.Join(workDir, "all_urls.txt")) - countLines(filepath.Join(workDir, "all_urls_200.txt")),

		// Phase 1 wired-up finders.
		ReflectionFindings:    reflectionFindings,
		ParamShapeFindings:    paramshapeFindings,
		AuthShapeFindings:     authshapeFindings,
		SignupTakeoverFindings: signupTakeoverFindings,
		IdorSurfaceFindings:   idorSurfaceFindings,
		OAuthFindings:         oauthFindings,
		RaceResults:           raceResults,
		BucketFindings:        bucketFindings,
		TakeoverV2Findings:    takeoverV2Findings,
		JSMineFindings:        jsMineFindings,

		// Phase 2 new finders.
		SecHeadersFindings:    secheadersFindings,
		BackupScanFindings:    backupscanFindings,
		BusinessLogicFindings: businesslogicFindings,
		HostHeaderFindings:    hostheaderFindings,
		CORS2Findings:         cors2Findings,

		// Phase 3 nuclei custom pass.
		NucleiRfufPass: nucleiRfufPass,
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
- **Hosts Tech-Fingerprinted:** %d

## Vulnerability Overview
- **RCE:** %d
- **Takeovers:** %d
- **LFI:** %d
- **SSRF:** %d
- **XSS:** %d
- **SQLi (sqlmap, confirmed only):** %d   *(raw candidate folders: %d)*
- **SQLi (ghauri, modern blind):** %d
- **Secrets:** %d
- **Backup / sensitive files exposed:** %d
- **Host header injection:** %d
- **Security header gaps:** %d
- **Credentialed CORS (preflight):** %d
- **Auth/JWT:** %d
- **CORS:** %d
- **FFUF (200-only verified):** %d
- **WAF Detections:** %d
- **Open Ports:** %d
- **Hidden Params:** %d

## Tech-Aware Findings
- **Discourse:** %d
- **Laravel / Livewire:** %d
- **WordPress:** %d
- **Cache Poisoning:** %d
- **JS Endpoints Discovered:** %d
- **JS Secrets Found:** %d
- **JS Endpoint Nuclei Hits:** %d

## High-Signal Methodology Modules
- **Reflection sites (html-body/attr-unquoted):** %d
- **HTTP Parameter Pollution divergence:** %d
- **Cookie / JWT misconfig:** %d
- **Signup email-verification flows:** %d
- **IDOR surface (per-param roll-up):** %d
- **OAuth redirect_uri bypass candidates:** %d
- **Race-condition candidates:** %d
- **Public buckets discovered:** %d
- **Service-specific takeovers (Vercel/Netlify/Fly/AzSWA):** %d
- **Deep JS bundle findings:** %d
- **Business-logic surface:** %d
- **Custom nuclei template hits:** %d

## Detailed report
Open [findings.md](./findings.md) — every URL to retest, grouped by
severity, with false-positive filtering transparent.
`, cp.Domain, cp.StartedAt.Format(time.RFC822), cp.LastUpdated.Format(time.RFC822), duration,
		subdomains, liveSubs, aliveHosts, len(techFingerprint),
		len(rce), len(takeovers), len(lfi), len(ssrf), len(xss),
		len(sqlmapConfirmed), countFolders(filepath.Join(workDir, "sqlmap_results")),
		len(ghauri),
		len(secrets)+len(potentialSecrets), len(auth), len(cors), len(ffuf),
		len(waf), len(ports), len(hiddenParams),
		len(discourse), len(laravel), len(wordpress), len(cachePoison),
		len(jsEndpoints), len(jsSecrets), len(jsEndpointFindings),
		len(reflectionFindings), len(paramshapeFindings), len(authshapeFindings),
		len(signupTakeoverFindings), len(idorSurfaceFindings), len(oauthFindings),
		len(raceResults), len(bucketFindings), len(takeoverV2Findings),
		len(jsMineFindings), len(businesslogicFindings), len(nucleiRfufPass),
		len(backupscanFindings), len(hostheaderFindings), len(secheadersFindings), len(cors2Findings))

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
	APISpecs        []string
	BOLATargets     []string
	NextjsPlaidJWT  []string

	// Tech-aware findings (Discourse / Laravel / WordPress / cache poison).
	DiscourseFindings   []string
	LaravelFindings     []string
	WordPressFindings   []string
	CachePoisonFindings []string

	// JS bundle artifacts.
	JSEndpoints        []string
	JSSecrets          []string
	JSEndpointFindings []string

	// Tech fingerprint rollup (per-host stack signal).
	TechFingerprint []string

	// Filtered-out appendix.
	DroppedSQLiCandidates []string
	DroppedURLTotal       int

	// Phase 1 wired-up finders (10 modules).
	ReflectionFindings     []string
	ParamShapeFindings     []string
	AuthShapeFindings      []string
	SignupTakeoverFindings []string
	IdorSurfaceFindings    []string
	OAuthFindings          []string
	RaceResults            []string
	BucketFindings         []string
	TakeoverV2Findings     []string
	JSMineFindings         []string

	// Phase 2 new finders (5 modules).
	SecHeadersFindings    []string
	BackupScanFindings    []string
	BusinessLogicFindings []string
	HostHeaderFindings    []string
	CORS2Findings         []string

	// Phase 3 custom nuclei template pass.
	NucleiRfufPass []string
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
	addSection(&sb, "Critical: API Spec Discovery (OpenAPI / Swagger / .well-known)", b.APISpecs,
		"API specs, OpenID configuration, and health endpoints discovered on alive hosts. Each [200] is the master endpoint list for the host's API — every downstream scanner (sqlmap, dalfox, nuclei) can be re-targeted at the spec's path list with templated UUIDs/IDs replaced.",
		"Download each spec into api_specs/<host>.* and `jq '.paths | keys'`. Probe every path with `httpx -mc 200` to see what's reachable unauthenticated. Any path that returns 200 without auth is the actual bug surface — the SPA hides these from the crawler but the spec exposes them. "+
			"[401-auth] entries indicate the spec EXISTS but is auth-walled — these are also high-value because they prove an internal API surface that you can attack once you have an authenticated session.")

	addSection(&sb, "Critical: BOLA Surface (UUID/object-reference params)", b.BOLATargets,
		"Endpoints with UUID-shaped query params (e.g. ?company=<uuid>, ?event=<uuid>) found in katana/gau output. Each is a candidate Broken Object Level Authorization (BOLA/IDOR) — the canonical 'change the ID, get someone else's data' bug. bola_curl.txt contains pre-built adjacent-UUID curl commands.",
		"Authenticate as User A in one cookie jar and User B in another. Run bola_curl.txt with each cookie. If User A's cookie can access User B's UUID, that's the report. "+
			"Adjacent-UUID probes alone (without auth) catch the case where the API has NO auth check at all — a 200 response to an adjacent UUID on an unauthenticated request is Critical.")

	addSection(&sb, "Critical: Next.js / Plaid / JWT Findings", b.NextjsPlaidJWT,
		"Stack-specific probes for Next.js middleware bypass (CVE-2025-29927), Plaid Link/Exchange endpoints, JWT alg:none acceptance, and Next.js source-map leaks.",
		"**Next.js middleware bypass**: the x-middleware-subrequest header skips Next.js middleware entirely. If a normally-auth-required path returns 200 with that header, the bypass works — full unauthenticated access. "+
			"**Plaid endpoints**: a Plaid Link/Exchange endpoint that returns 200 unauthenticated can leak access_tokens for any user the attacker knows the public_token of. "+
			"**JWT alg:none**: a forged `eyJhbGciOiJub25lIi...` token with no signature being accepted means the server is vulnerable to algorithm confusion. Replicate with `jwt_tool` and document. "+
			"**Source maps**: download the .map file and grep for hardcoded keys, API URLs, internal endpoints — the source map IS the source code.")

	addSection(&sb, "Critical: Laravel / Livewire Findings", b.LaravelFindings,
		"Exposed Laravel endpoints: /.env, /horizon, /telescope, /livewire/update CSRF bypass, debug mode, APP_KEY leak.",
		"If .env is exposed, read it directly — DB creds, mail creds, AWS keys are the report. APP_KEY leak = full RCE via `php artisan`. "+
			"Debug mode (Whoops/Stack trace) discloses full stack + env vars to anyone hitting a 404.")

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

	addSection(&sb, "High: Discourse Findings", b.DiscourseFindings,
		"Discourse forum-specific exposures: publicly accessible /admin, /sidekiq, vulnerable version, Onebox SSRF, missing API auth.",
		"If /admin or /sidekiq returns 200, the impact ranges from RCE (Sidekiq eval console) to full forum compromise. "+
			"Cross-check version against https://github.com/discourse/discourse/security/advisories — known CVEs often don't require auth.")

	addSection(&sb, "High: Cache Poisoning", b.CachePoisonFindings,
		"Cache poisoning via unkeyed headers (X-Forwarded-Host, X-Original-URL, X-Host, X-Forwarded-Server) on CDN-fronted hosts.",
		"Confirm: re-fetch the poisoned URL from a different IP/region (or via a different egress proxy) and verify the malicious content is cached and served to other users. "+
			"Local-only reflection is not enough — the cache must be poisoned globally for the report to land.")

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

	addSection(&sb, "Medium: WordPress Findings", b.WordPressFindings,
		"WordPress-specific misconfigs: xmlrpc enabled, wp-config.php.bak exposed, user enumeration via /?author=, exposed /wp-json.",
		"xmlrpc enabled + brute force = mass credential stuffing. wp-config backup = DB creds in plaintext. "+
			"User enumeration reveals admin usernames — combine with credential stuffing for a chain.")

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
		"WAF vendor fingerprinting — drives the auto-applied tamper for sqlmap and dalfox (see buildWafTamperSnippet).",
		"Detected WAF auto-applies a tamper catalog: Cloudflare/Cloudfront → between,randomcase,space2comment (sqlmap) + wasm (dalfox); "+
			"AWS → randomcase,space2plus + utf-8; Imperva → randomcase,between,space2comment + html; Akamai → + versionedkeywords; "+
			"F5 → space2mysqldash; Barracuda → unionalltounion; Sucuri → modsecurityversioned; Fastly → between,randomcase. "+
			"Unknown vendor → between + html (mild default). Override the catalog in internal/findings/internal/wafbypass. "+
			"For WAF vendor-by-vendor counts (instead of every host), see `waf_vendor_summary.txt`.")

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

	addSection(&sb, "Info: JS Endpoint Nuclei Hits", b.JSEndpointFindings,
		"Nuclei hits against endpoints discovered in JS bundles (token-spray, exposure, misconfig tags).",
		"JS bundles often contain API endpoints the crawler can't reach directly. Each nuclei hit here came from an endpoint found only via static JS analysis. "+
			"Re-run the nuclei template manually to confirm the hit, then verify it's in scope before reporting.")

	addSection(&sb, "Info: Tech Fingerprint", b.TechFingerprint,
		"Per-host technology stack fingerprint — drives tech-specific probes.",
		"Drives the Discourse / Laravel / WordPress / cache-poison stages. Use this to prioritize manual review of hosts with deeper attack surface "+
			"(Laravel debug-mode hosts, Discourse forum hosts with /admin accessible, CDN-fronted hosts).")

	addSection(&sb, "Info: JS Endpoints Discovered", b.JSEndpoints,
		"API endpoints extracted from JS bundles and source maps — not reachable via direct crawl.",
		"These endpoints were not crawled by katana (they're behind JS loading). Each is a candidate for manual IDOR / auth / input-validation testing. "+
			"Prioritize endpoints under /api/, /admin/, /internal/ — they're the most likely to lack auth checks.")

	addSection(&sb, "Info: JS Bundle Secrets", b.JSSecrets,
		"API keys, tokens, or credentials embedded in JS bundles / source maps.",
		"Verify the key authenticates against the relevant service (do not assume — many are stale or test keys). "+
			"DO NOT paste the secret in your report — disclose via the platform's secure form. Common false positives: Google API keys with referrer restrictions.")

	// ====================================================================
	// === Phase 1: wired-up high-signal methodology modules ================
	// ====================================================================

	// ─── CRITICAL ────────────────────────────────────────────────────────
	addSection(&sb, "Critical: Backup / Sensitive File Exposure", b.BackupScanFindings,
		"Sensitive files exposed via direct URL (.env, .git/HEAD, wp-config.php.bak, db.sql, id_rsa, .aws/credentials, ...).",
		"Each hit is the file's *contents* — that's the report. Read the file directly with curl. "+
			"For .env: DB creds, mail creds, AWS keys, signed-cookie salts. For .git/HEAD: use git-dumper to clone the repo. "+
			"For db.sql: full DB dump. NEVER paste the contents in your report — disclose via the platform's secure form.")

	addSection(&sb, "Critical: Public Cloud Buckets", b.BucketFindings,
		"S3/GCS/Azure bucket exists and is publicly listable.",
		"Open the bucket URL in a browser. The file listing IS the report. Note: public-listable ≠ public-write; "+
			"public-write is critical RCE risk if the bucket backs a static site or Lambda deployment.")

	addSection(&sb, "Critical: Deep JS Bundle Findings", b.JSMineFindings,
		"Hardcoded secrets, internal POST endpoints, admin paths, S3 URLs, GraphQL mutations extracted from JS bundles.",
		"Secrets: verify the key authenticates against the relevant service. POST endpoints: each is a manual-retest target for IDOR/auth-bypass. "+
			"GraphQL mutations (e.g. `deleteUser`, `updateBilling`) are higher-impact than queries.")

	// ─── HIGH ────────────────────────────────────────────────────────────
	addSection(&sb, "High: Reflection Sites (html-body / attr-unquoted)", b.ReflectionFindings,
		"Per-URL classification of where query parameters are reflected. html-body / attr-unquoted sites are practically XSS-confirmed.",
		"Open each URL with the marker in the URL bar. The site classification tells you which dalfox payload will land. "+
			"For attr-unquoted: `><svg onload=alert(1)>` (no quote escape needed). For html-body: standard `<script>alert(1)</script>`.")

	addSection(&sb, "High: Signup Email-Verification Flows", b.SignupTakeoverFindings,
		"Sites exposing signup endpoints with email-verification URL patterns.",
		"Sign up with a controlled email (use mailtrap or your own domain). Intercept the verification email. "+
			"Test: (1) is the token sequential / guessable? (2) is the same token reusable for any other email address? "+
			"A reusable token is a full account-takeover class on most programs.")

	addSection(&sb, "High: HTTP Parameter Pollution", b.ParamShapeFindings,
		"Same param submitted in different shapes (?id=1, ?id[]=1, ?id=1&id=2, mixed case, null byte) yields different responses.",
		"HPP = the backend reads a different value than the frontend sends. Common in PHP/ASP/J2EE. "+
			"Test: change the duplicate value and see if the action mutates the state. Often combined with privilege escalation.")

	addSection(&sb, "High: Cookie / JWT Misconfigurations", b.AuthShapeFindings,
		"Missing HttpOnly/Secure/SameSite on session cookies; alg:none or missing exp in JWTs.",
		"For alg:none: re-issue the same token with header `{\"alg\":\"none\"}` and empty signature. If the server accepts it, "+
			"forging tokens is trivial. For HttpOnly missing: combine with a stored XSS to steal the session cookie.")

	addSection(&sb, "High: Host Header Injection", b.HostHeaderFindings,
		"Server reflects attacker-controlled Host / X-Forwarded-Host / X-Original-URL in body or Location.",
		"Exploitable for: (1) password-reset poisoning — trigger a reset, intercept the email, see if your host is in the link. "+
			"(2) cache poisoning — re-fetch the URL from a different egress IP to confirm global cache. "+
			"(3) SSRF — sometimes the Host is used to build a callback URL.")

	addSection(&sb, "High: Credentialed CORS (preflight)", b.CORS2Findings,
		"OPTIONS preflight allows attacker origin + credentials; or null-origin reflected with credentials.",
		"Drop a credentialed XHR from a controlled origin to the target endpoint. If the request succeeds AND the response is readable, "+
			"you have cross-origin data exfil. Modern browsers enforce this less strictly than you think — null-origin alone via sandboxed iframe is a real bug.")

	addSection(&sb, "High: Service-Specific Takeovers", b.TakeoverV2Findings,
		"Vercel/Netlify/Fly.io/Azure Static Web Apps fingerprints indicating the underlying service has been deleted.",
		"Register the deleted service with the same name. If the CNAME is still pointing to it, you control the subdomain. "+
			"Cookie-bite the parent domain before reporting — most programs want the parent+sub chain, not just the dangling CNAME.")

	addSection(&sb, "High: OAuth redirect_uri Bypass Candidates", b.OAuthFindings,
		"Per-host authorize endpoint with 5 ready-to-curl bypass payloads per allowlist entry.",
		"Each candidate row includes a curl one-liner. Run the request with a fresh client_id; a 302 to the attacker's domain with the auth code is the report. "+
			"Most common: subdomain-bypass and path-traversal. Note: most programs prohibit active probing of the auth flow — disclose the candidate list, not the exploit.")

	addSection(&sb, "High: Race-Condition Candidates", b.RaceResults,
		"URLs matching business-logic keywords where 20 concurrent requests with unique markers succeeded (TOCTOU signal).",
		"Repeat the test with a setup where the action has visible state (coupon balance, vote count, withdrawal amount). "+
			"For payment: time the requests within the same TCP/TLS connection (single-connection multiplex). "+
			"For coupon: race 50 requests; report the count of times the coupon was applied N times to a single balance.")

	// ─── MEDIUM ──────────────────────────────────────────────────────────
	addSection(&sb, "Medium: IDOR Surface Map", b.IdorSurfaceFindings,
		"Per-param roll-up of object-reference parameters (id, user_id, account_id, ...) across hosts.",
		"Set up two test accounts (A and B). For each param in this list, replay the URL as A, capture the response, "+
			"then replay as B. If B sees A's data → IDOR. High-yield params: user_id, account_id, order_id, doc_id, "+
			"profile_id, reservation_id, invoice_id. The roll-up tells you which params are worth setting up two accounts for.")

	addSection(&sb, "Medium: Business-Logic Surface", b.BusinessLogicFindings,
		"URLs matching pricing/coupon/balance/vote/gift/payment/currency/points keywords, sorted by suspicious-param shape.",
		"Authenticate, then for each URL: try negative quantity, zero price, currency mismatch (USD-priced-but-EUR-charged), "+
			"role/admin param swap. Each is a manual-retest candidate — auto-pivots on this surface are too noisy to run safely.")

	addSection(&sb, "Medium: Security Header Gaps", b.SecHeadersFindings,
		"Missing or weak CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP.",
		"Missing CSP on a site with user content is XSS-class. Missing HSTS on HTTPS is MITM-class. "+
			"For each gap: prioritize hosts that handle auth or PII. Headers are often scoped to a single endpoint pattern — re-fetch the actual auth page, not just the homepage.")

	// ─── INFO ────────────────────────────────────────────────────────────
	addSection(&sb, "Info: Custom Nuclei Template Hits", b.NucleiRfufPass,
		"Custom nuclei templates run against alive.txt — debug endpoints, SaaS tokens, JWT alg:none, host-header, CORS.",
		"Each hit has a template id (`rfuf-*`). Re-run with `nuclei -t nuclei-templates-rfuf/ -id <template-id> -l <host> -debug` to confirm.")

	// ─── APPENDIX: WHAT WAS FILTERED OUT ─────────────────────────────────
	sb.WriteString("---\n\n## What was filtered out (false positives removed)\n\n")
	sb.WriteString(fmt.Sprintf("- **URLs pruned for not responding testable:** %d endpoints from gau/wayback/katana "+
		"were dropped before the vuln scanners. The filter accepts 200, 301, 302, 401, 403, 405; everything else (404, 500, timeouts) is excluded. "+
		"401/403/405 are kept because they represent real endpoints that simply require auth or only respond to other methods.\n",
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
