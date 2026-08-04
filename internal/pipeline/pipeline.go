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

// effectiveStepTimeout returns the smaller of global vs per-step timeout.
// If either is 0 (the "no limit" sentinel from a CLI flag), the other is
// used unchanged. Stages that know their max bounded runtime (gau, naabu,
// etc.) get a tighter ceiling; the global cap still applies to all other
// stages as a last-resort backstop.
func effectiveStepTimeout(global, perStep time.Duration) time.Duration {
	switch {
	case perStep == 0:
		return global
	case global == 0:
		return perStep
	case perStep < global:
		return perStep
	default:
		return global
	}
}

type Step struct {
	ID      string
	Command string
	Type    string // "default", "grep"
	Deps    []string
	// Timeout is the per-step wall-clock cap. 0 = inherit the global
	// -step-timeout. Set this on stages whose known-bounded runtime is
	// much smaller than the global default so a stuck child gets killed
	// quickly instead of after the global timeout expires. Stages that
	// benefit: gau, waybackurls, naabu, trufflehog.
	Timeout time.Duration
}

var (
	uiLock sync.Mutex

	// nucleiOptimized provides better performance for large scans.
	//
	// `-retries 1` is critical: without it, every transient connection
	// failure (TLS reset, slow host, Cloudflare 5xx) triggers a retry that
	// gets counted as a separate "error" in nuclei stats. On a large
	// target with thousands of alive hosts we previously observed 1.35
	// million accumulated errors and a 37 % error rate — none of which
	// were real findings, all of which were the retry budget burning
	// through 3 attempts × every transient failure × every template.
	// `-retries 1` keeps the failure as a single attempt and stops the
	// error counter from dominating the run.
	nucleiOptimized = " -rl 300 -c 50 -bs 25 -timeout 5 -retries 1 -silent -stats -stats-interval 30"

	// maxScanTargets caps gf/grep output
	maxScanTargets = 5000

	// urlMinerTimeout is the per-process wall-clock cap for gau /
	// waybackurls. Both tools iterate every host sequentially against
	// upstream APIs (wayback, Common Crawl, OTX). On a target with
	// thousands of alive hosts the historical data can take 30+ minutes
	// per host if the API rate-limits. A hard 10-minute cap protects
	// the pipeline from hanging forever; the stage downstream of
	// `merge_all_urls` operates fine with whatever subset was produced.
	urlMinerTimeout = "10m"

	// sqlmapScanTimeout bounds the entire `sqlmap -m sqli_targets.txt`
	// batch. Even capped to 300 targets, a single slow param or a
	// time-based blind test against a stalled host can keep sqlmap busy
	// for 15+ minutes; without a ceiling, a wedged backend pins the
	// pipeline's "active stages" line forever. `timeout --foreground`
	// below sends SIGTERM cleanly to the whole process group; we follow
	// with `|| true` so the stage still exits 0 on timeout and the
	// checkpoint records it as completed (any partial sqlmap_results/
	// output is preserved). 15m lets a real SQLi on most targets finish
	// while guaranteeing no single stage can block past the next tick.
	sqlmapScanTimeout = "15m"

	// xssScanTimeout bounds the Gxss → dalfox pipe. `Gxss -p khXSS`
	// amplifies every XSS candidate into multiple variants before
	// handing them to dalfox, so the input list can grow by 5–10× before
	// dalfox even starts. Combined with dalfox's per-target browser
	// checks (Chromedp / headless Chrome), this stage can exceed 30 min
	// on a 300-url input. 10m is plenty for a high-signal pass; the
	// captured `xss_vulnerabilities.txt` is also stored as partial so
	// each resume picks up incremental findings.
	xssScanTimeout = "10m"

	// xssScanTargetCap mirrors sqlmapTargetCap. dalfox's per-target
	// runtime is highly variable (a single chatty endpoint with many
	// params can hold the browser pool for minutes), so even with the
	// 10-minute wall-clock cap the stage only succeeds if the input
	// stays bounded. 500 is a tight ceiling that still catches every
	// realistic reflection point: gf xss already filtered to high-signal
	// query-param-bearing URLs.
	xssScanTargetCap = 500

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

// filterTestableRef is the documented path to the filter_testable binary
// that the pipeline invokes to clean its target lists. The pipeline uses
// `go run ./cmd/filter-testable` (resolved at execution time) so we don't
// need a separate `go build` step — Go's toolchain compiles on demand.
//
// Note: this previously pointed at `./internal/filter` but that path is
// a library (no `package main`), so the runtime resolution silently
// failed at scan time. `cmd/filter-testable` is the dedicated `package
// main` wrapper that calls `filter.FilterFile()` and emits URLs on
// stdout.
const filterTestableRef = "go run ./cmd/filter-testable"

// findingsRunnerRef is the dispatch wrapper for every Go module under
// internal/findings/<name>/. The pipeline invokes each finder as
//
//	go run ./cmd/findings-runner <finder-name> <workdir>
//
// and the runner dispatches to the right module's Run() function.
// Adding a new finder = (1) Run(workdir) in internal/findings/<name>
// (2) an entry in cmd/findings-runner/main.go's dispatch map (3) a
// new Step here. The runner exits 0 on no-findings so every step
// succeeds even when the input is empty / missing.
const findingsRunnerRef = "go run ./cmd/findings-runner"

// buildAuthHeaderSnippet returns a shell fragment that yields the auth
// headers (or empty) for tools that accept -H flags. Used as a prefix to
// httpx, nuclei, and curl commands.
//
// Stage commands reference this via:
//
//   AUTH_HEADERS=$(buildAuthHeaderSnippet_shell)
//   httpx -l alive.txt $AUTH_HEADERS ...
//
// Implemented as a shell function in the stage command's preamble so each
// tool can `${AUTH_HEADERS:+...}` for backward compat.
func buildAuthHeaderSnippet() string {
	return `
build_auth_headers() {
  local h=""
  [ -n "$RFUF_AUTH_COOKIE" ] && h="$h -H Cookie:$RFUF_AUTH_COOKIE"
  [ -n "$RFUF_AUTH_HEADER" ] && h="$h -H Authorization:$RFUF_AUTH_HEADER"
  echo "$h"
}
AUTH_HEADERS="$(build_auth_headers)"
AUTH_HEADERS="${AUTH_HEADERS# }"
`
}

// GetSteps returns the ordered list of pipeline stages. Each entry is a
// self-contained bash one-liner that the executor runs. The stages are
// grouped by phase:
//
//   Phase 1 — Recon            (subfinder, assetfinder, amass, dnsx, brute)
//   Phase 2 — Probing          (httpx, tech fingerprint, takeover, waf, ports)
//   Phase 3 — Tech-specific    (Discourse, Laravel, WordPress, cache-poison)
//   Phase 4 — URL mining       (katana, gau, wayback, jsmap scrape)
//   Phase 5 — Secret scanning  (trufflehog, grep)
//   Phase 6 — Host enumeration (URL filter, target lists, vuln scans)
//   Phase 7 — Reconnaissance   (cors, ffuf, hidden params, manual review)
//
// Auth + OOB are wired through every scanner command via the
// RFUF_AUTH_COOKIE / RFUF_AUTH_HEADER / RFUF_OOB_URL env vars set by
// executor.RunCommand. Empty values mean the auth/OOB flags are skipped
// silently via shell `${var:+...}` expansion.
//
// Total stage count: ~56 (was 46). New stages: subdomain_brute,
// merge_brute_subs, tech_fingerprint, discourse_probes, laravel_probes,
// wordpress_probes, cache_poison_probe, jsmap_scrape, js_endpoints_scan.
// Existing stages modified: httpx_probe, url_filter_alive, sqli_targets,
// xss_targets, idor_targets, ssrf_targets, rce_targets, redirect_targets,
// lfi_targets, sqlmap_scan, xss_scan, rce_scan, idor_scan, ssrf_scan,
// cors_check, dirbrute_ffuf, grep_secrets.
func GetSteps(domain string, paths *config.Paths) []Step {
	domainEscaped := strings.ReplaceAll(domain, ".", "\\.")
	wordlist := pickWordlist(paths)
	authSnip := buildAuthHeaderSnippet()

	// oobSubstitute is a one-liner that writes a target file with
	// ${OOB} placeholders expanded to the actual interactsh URL. Used by
	// SSRF/RCE/XSS stages to inject blind-callback URLs.
	oobSubstitute := func(in, out string) string {
		return fmt.Sprintf("sed 's|${OOB}|%s|g' %s > %s", "${RFUF_OOB_URL}", in, out)
	}

	_ = oobSubstitute // used via inline references in commands below

	return []Step{
		{"setup_directories", fmt.Sprintf("mkdir -p %s", paths.WorkDir), "default", nil, 0},
		{"subfinder", fmt.Sprintf("subfinder -d %s -all -o subfinder.txt", domain), "default", []string{"setup_directories"}, 0},
		{"assetfinder", fmt.Sprintf("assetfinder --subs-only %s > assetfinder.txt", domain), "default", []string{"setup_directories"}, 0},
		// amass_enum: bound the runtime inside the command itself. amass
		// defaults to active enumeration (zone transfers, cert grabs,
		// recursive brute forcing) which can run for many hours on a
		// non-trivial target. -passive skips all of that and uses only
		// the data-source APIs, finishing in minutes. -timeout 30 is
		// defense in depth: even if the global -step-timeout is disabled,
		// amass still exits in 30 minutes.
		{"amass_enum", fmt.Sprintf("amass enum -passive -norecursive -timeout 30 -d %s -o amass_raw.txt", domain), "default", []string{"setup_directories"}, 0},
		// amass_parse: `amass -o file.txt` writes one subdomain per line.
		// grep -F treats the domain as a fixed string. Added file check for resilience.
		{"amass_parse", fmt.Sprintf("[ -f amass_raw.txt ] && grep -F \"%s\" amass_raw.txt | sort -u > amass_sub.txt || touch amass_sub.txt", domain), "grep", []string{"amass_enum"}, 0},
		{"merge_subs", "touch subfinder.txt assetfinder.txt amass_sub.txt; cat subfinder.txt assetfinder.txt amass_sub.txt | sort -u > subs.txt", "default", []string{"subfinder", "assetfinder", "amass_parse"}, 0},
		{"dnsx_resolve", "dnsx -l subs.txt -silent -o live_subs.txt", "default", []string{"merge_subs"}, 0},

		// === NEW: Subdomain brute (catches staging/dev that CT logs miss) ===
		{"subdomain_brute", `set +e
: > brute_subs.txt
SUBS="www mail smtp pop pop3 imap ftp sftp webmail email mx mx1 mx2 remote vpn admin administrator dashboard panel cpanel whm webdisk ns ns1 ns2 ns3 ns4 dns dns1 dns2 api api2 api3 api-v1 api-v2 backend back backoffice internal intranet staging stage stg dev develop development test testing qa uat sandbox demo preview pre prod production live old legacy beta alpha v1 v2 v3 new blog blogs forum forums community help helpdesk support docs documentation wiki kb faq status monitor monitoring jenkins gitlab github bitbucket jira confluence crm erp hr portal gateway auth login sso saml oauth id identity accounts account user users member members customer customers client clients partner partners vendor vendors billing invoice invoices payment payments pay shop store checkout cart order orders search find cdn cdn1 cdn2 static assets img images media files upload uploads download downloads data db database mysql postgres postgresql mongo redis elastic elasticsearch sentry newrelic app application apps web web1 web2 web3 web4 web5 mobile m mobi android ios push notification notifications events stream analytics track tracking tag tags pixel redirect proxy cache edge lb loadbalancer"
for sub in $SUBS; do
  if getent hosts "${sub}.${RFUF_DOMAIN}" >/dev/null 2>&1; then
    echo "${sub}.${RFUF_DOMAIN}" >> brute_subs.txt
  fi
done
sort -u brute_subs.txt -o brute_subs.txt
exit 0`, "grep", []string{"dnsx_resolve"}, 0},

		{"merge_brute_subs", "cat subs.txt brute_subs.txt | sort -u > subs_with_brute.txt && mv subs_with_brute.txt live_subs.txt", "default", []string{"subdomain_brute"}, 0},

		{"subzy_takeover", "subzy run --targets live_subs.txt --vuln | tee subzy_vulnerable.txt", "default", []string{"merge_brute_subs"}, 0},
		{"extract_takeover_targets", fmt.Sprintf("grep \"VULNERABLE\" subzy_vulnerable.txt | grep -oE '[a-zA-Z0-9._-]+\\.%s' | sort -u > takeover_targets.txt", domainEscaped), "grep", []string{"subzy_takeover"}, 0},
		{"validate_takeovers", fmt.Sprintf("nuclei -l takeover_targets.txt -t %s/http/takeovers/ %s -o validated_takeovers.txt", paths.NucleiTemplates, nucleiOptimized), "default", []string{"extract_takeover_targets"}, 0},

		// httpx_probe now injects auth headers (when -auth-cookie/-auth-bearer set)
		{"httpx_probe", fmt.Sprintf(`%s
[ -s live_subs.txt ] && httpx -l live_subs.txt -silent $AUTH_HEADERS -o alive.txt || : > alive.txt`, authSnip), "default", []string{"merge_brute_subs"}, 0},

		// === NEW: Tech fingerprinting — drives Discourse/Laravel/WordPress stages ===
		{"tech_fingerprint", `set +e
: > tech_fingerprint.txt
while read HOST; do
  TECH=""
  HEADERS=$(curl -sk --max-time 8 -I "$HOST" 2>/dev/null)
  BODY=$(curl -sk --max-time 8 "$HOST" 2>/dev/null | head -c 50000)
  echo "$HEADERS" | grep -qi "X-Discourse" && TECH="${TECH}discourse,"
  echo "$BODY" | grep -qi "Discourse" && TECH="${TECH}discourse,"
  echo "$HEADERS" | grep -qi "XSRF-TOKEN" && TECH="${TECH}laravel,"
  echo "$BODY" | grep -qi "livewire" && TECH="${TECH}laravel,"
  echo "$BODY" | grep -q "__NEXT_DATA__" && TECH="${TECH}nextjs,"
  echo "$HEADERS" | grep -qi "Next.js" && TECH="${TECH}nextjs,"
  WPCODE=$(curl -sk --max-time 5 "$HOST/wp-login.php" -o /dev/null -w "%{http_code}" 2>/dev/null)
  case "$WPCODE" in 200|302) TECH="${TECH}wordpress," ;; esac
  echo "$HEADERS" | grep -qi "X-Drupal" && TECH="${TECH}drupal,"
  echo "$HEADERS" | grep -qi "heroku" && TECH="${TECH}heroku,"
  echo "$HEADERS" | grep -qi "Fastly" && TECH="${TECH}fastly,"
  echo "$HEADERS" | grep -qi "cloudflare" && TECH="${TECH}cloudflare,"
  echo "$HEADERS" | grep -qi "cf-ray" && TECH="${TECH}cloudflare,"
  [ -n "$TECH" ] && echo "$HOST  $TECH" >> tech_fingerprint.txt
done < alive.txt
exit 0`, "grep", []string{"httpx_probe"}, 0},

		{"nuclei_exposures", fmt.Sprintf("nuclei -l alive.txt -tags token-spray,exposure,config -severity medium,high,critical %s -o credentials_found.txt", nucleiOptimized), "default", []string{"httpx_probe"}, 0},
		{"nuclei_misconfigs", fmt.Sprintf("nuclei -l alive.txt -tags misconfig,exposure,panel %s -o misconfigs.txt", nucleiOptimized), "default", []string{"httpx_probe"}, 0},
		{"nuclei_auth_scan", fmt.Sprintf("nuclei -l alive.txt -tags jwt,auth-bypass,default-login %s -o auth_results.txt", nucleiOptimized), "default", []string{"httpx_probe"}, 0},
		// GraphQL templates are maintained across multiple directories in nuclei-templates.
		{"nuclei_graphql_scan", fmt.Sprintf("nuclei -l alive.txt -tags graphql %s -o graphql_exposed.txt", nucleiOptimized), "default", []string{"httpx_probe"}, 0},

		// === NEW: Discourse-specific probes (admin, sidekiq, version, Onebox) ===
		{"discourse_probes", `set +e
: > discourse_findings.txt
mkdir -p discourse_findings
while read LINE; do
  HOST=$(echo "$LINE" | awk '{print $1}')
  [ -z "$HOST" ] && continue
  OUT="discourse_findings/$(echo "$HOST" | sed 's|https\?://||;s|/|_|g').txt"
  {
    echo "=== version ==="
    curl -sk --max-time 10 "$HOST/about.json" | jq -r '.about.version // empty' 2>/dev/null
    echo "=== users_count ==="
    curl -sk --max-time 10 "$HOST/about.json" | jq -r '.about.stats.users_count // empty' 2>/dev/null
    echo "=== sidekiq exposed? ==="
    curl -sk --max-time 10 -o /dev/null -w "%{http_code}" "$HOST/sidekiq"
    echo
    echo "=== /admin accessible? ==="
    curl -sk --max-time 10 -o /dev/null -w "%{http_code}" "$HOST/admin"
    echo
    echo "=== Onebox SSRF ==="
    curl -sk --max-time 10 -G --data-urlencode "url=http://example.com" "$HOST/onebox" -o /dev/null -w "%{http_code}"
    echo
    echo "=== /chat enabled? ==="
    curl -sk --max-time 10 -o /dev/null -w "%{http_code}" "$HOST/chat"
    echo
  } > "$OUT" 2>&1
  # Aggregate findings
  if grep -qE "^200$" "$OUT" 2>/dev/null; then
    grep -B1 "^200$" "$OUT" | grep -qE "sidekiq" && echo "[HIGH] $HOST — /sidekiq exposed (200)" >> discourse_findings.txt
    grep -B1 "^200$" "$OUT" | grep -qE "/admin" && echo "[CRITICAL] $HOST — /admin publicly accessible (200)" >> discourse_findings.txt
  fi
done < tech_fingerprint.txt
exit 0`, "grep", []string{"tech_fingerprint"}, 0},

		// === NEW: Laravel / Livewire probes (.env, horizon, telescope, debug) ===
		{"laravel_probes", `set +e
: > laravel_findings.txt
mkdir -p laravel_findings
while read LINE; do
  HOST=$(echo "$LINE" | awk '{print $1}')
  [ -z "$HOST" ] && continue
  OUT="laravel_findings/$(echo "$HOST" | sed 's|https\?://||;s|/|_|g').txt"
  {
    echo "=== .env ==="
    curl -sk --max-time 10 "$HOST/.env" -o /dev/null -w "%{http_code}"
    echo
    echo "=== /horizon ==="
    curl -sk --max-time 10 "$HOST/horizon" -o /dev/null -w "%{http_code}"
    echo
    echo "=== /telescope ==="
    curl -sk --max-time 10 "$HOST/telescope" -o /dev/null -w "%{http_code}"
    echo
    echo "=== /livewire/update ==="
    curl -sk --max-time 10 -X POST "$HOST/livewire/update" \
      -H "Content-Type: application/json" \
      -H "X-Livewire: 1" \
      -H "X-CSRF-TOKEN: x" \
      -d '{"_token":"x","components":[{"snapshot":"{}","updates":{},"calls":[]}]}' \
      -o /dev/null -w "%{http_code}"
    echo
    echo "=== /api/ unauth ==="
    for PATH in /api/user /api/users /api/admin /api/v1/user /api/v1/users; do
      curl -sk --max-time 5 "$HOST$PATH" -o /dev/null -w "  $PATH %{http_code}\n"
    done
    echo
    echo "=== debug mode ==="
    DEBUG_PAGE=$(curl -sk --max-time 10 "$HOST/nonexistent-route-xyz123rfuf" 2>/dev/null)
    echo "$DEBUG_PAGE" | grep -qi "Whoops" && echo "WHOOPS debug ON" || echo "no debug"
    echo "$DEBUG_PAGE" | grep -qi "Stack trace" && echo "STACK TRACE exposed"
    echo "=== APP_KEY leak ==="
    echo "$DEBUG_PAGE" | grep -ioE '"APP_KEY"[^,]{20,}' || true
  } > "$OUT" 2>&1
  grep -qE "^\.env +200" "$OUT" 2>/dev/null && echo "[CRITICAL] $HOST/.env exposed (200)" >> laravel_findings.txt
  grep -qE "^/horizon +200" "$OUT" 2>/dev/null && echo "[HIGH] $HOST/horizon exposed" >> laravel_findings.txt
  grep -qE "^/telescope +200" "$OUT" 2>/dev/null && echo "[HIGH] $HOST/telescope exposed" >> laravel_findings.txt
  grep -qE "WHOOPS debug ON" "$OUT" 2>/dev/null && echo "[HIGH] $HOST debug mode enabled" >> laravel_findings.txt
  grep -qiE "APP_KEY=base64:" "$OUT" 2>/dev/null && echo "[CRITICAL] $HOST APP_KEY leaked" >> laravel_findings.txt
done < tech_fingerprint.txt
exit 0`, "grep", []string{"tech_fingerprint"}, 0},

		// === NEW: WordPress-specific probes (xmlrpc, wp-config, user enum) ===
		{"wordpress_probes", `set +e
: > wordpress_findings.txt
mkdir -p wordpress_findings
while read LINE; do
  HOST=$(echo "$LINE" | awk '{print $1}')
  [ -z "$HOST" ] && continue
  OUT="wordpress_findings/$(echo "$HOST" | sed 's|https\?://||;s|/|_|g').txt"
  {
    echo "=== /wp-json/wp/v2/users ==="
    curl -sk --max-time 10 "$HOST/wp-json/wp/v2/users" | jq -r '.[].slug // empty' 2>/dev/null | head -10
    echo
    echo "=== /xmlrpc.php ==="
    curl -sk --max-time 10 -X POST "$HOST/xmlrpc.php" \
      -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>' \
      -o /dev/null -w "%{http_code}"
    echo
    echo "=== /wp-cron.php ==="
    curl -sk --max-time 10 -o /dev/null -w "%{http_code}" "$HOST/wp-cron.php"
    echo
    echo "=== author enumeration ==="
    for N in 1 2 3 4 5; do
      REDIR=$(curl -sk --max-time 5 -o /dev/null -w "%{redirect_url}" "$HOST/?author=$N" 2>/dev/null)
      echo "  author=$N $REDIR"
    done
    echo "=== wp-config backups ==="
    for SUFFIX in .bak .backup .old .save ~ .txt .swp; do
      CODE=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "$HOST/wp-config.php$SUFFIX" 2>/dev/null)
      [ "$CODE" = "200" ] && echo "  wp-config.php$SUFFIX 200 EXPOSED"
    done
  } > "$OUT" 2>&1
  grep -q "EXPOSED" "$OUT" 2>/dev/null && echo "[CRITICAL] $HOST wp-config backup exposed" >> wordpress_findings.txt
  grep -qE "author=1 https?://" "$OUT" 2>/dev/null && echo "[MEDIUM] $HOST user enumeration via /?author=" >> wordpress_findings.txt
done < tech_fingerprint.txt
exit 0`, "grep", []string{"tech_fingerprint"}, 0},

		// === NEW: Cache poisoning probes on CDN-fronted hosts ===
		{"cache_poison_probe", `set +e
: > cache_poison_findings.txt
mkdir -p cache_poison_results
while read LINE; do
  HOST=$(echo "$LINE" | awk '{print $1}')
  TECH=$(echo "$LINE" | awk '{print $2}')
  echo "$TECH" | grep -qE "cloudflare|fastly|cloudfront" || continue
  OUT="cache_poison_results/$(echo "$HOST" | sed 's|https\?://||;s|/|_|g').txt"
  {
    echo "=== baseline ==="
    curl -sk --max-time 8 -I "$HOST" 2>/dev/null | head -3
    for HEADER in "X-Forwarded-Host: evil.com" "X-Original-URL: /evil" "X-Host: evil.com" "X-Forwarded-Server: evil.com"; do
      RESP=$(curl -sk --max-time 8 -H "$HEADER" "$HOST" 2>/dev/null)
      if echo "$RESP" | grep -qi "evil.com"; then
        echo "[VULN] header '$HEADER' reflected"
        echo "$RESP" | grep -i "evil.com" | head -1 | cut -c1-200
      fi
    done
  } > "$OUT" 2>&1
done < tech_fingerprint.txt
grep -rh "\[VULN\]" cache_poison_results/ 2>/dev/null | sort -u > cache_poison_findings.txt
exit 0`, "grep", []string{"tech_fingerprint"}, 0},

		// katana crawl with auth headers
		{"katana_crawl", fmt.Sprintf(`%s
[ -s alive.txt ] && katana -list alive.txt -jc -kf all -d 3 -fs rdn %s -o katana_urls.txt || touch katana_urls.txt`, authSnip, "${AUTH_HEADERS:+(Header is via HEAD/GET only)}"), "default", []string{"httpx_probe"}, 0},

		{"clean_urls", fmt.Sprintf("grep -Ei '^https?://([a-zA-Z0-9-]+\\.)*%s' katana_urls.txt | grep -Ev '\\.(css|js|png|jpg|jpeg|gif|pdf|svg|ico)($|\\?)' | sed 's/\\\\$//' | sort -u > clean_katana_urls.txt", domainEscaped), "grep", []string{"katana_crawl"}, 0},

		// === NEW: JS bundle scraping — extract endpoints/keys from JS that
		// katana missed (loaded via JS navigation, not direct links).
		{"jsmap_scrape", `set +e
mkdir -p js_bundles endpoints_found js_secrets
while read HOST; do
  PREFIX=$(echo "$HOST" | sed 's|https\?://||;s|/|_|g;')
  JS_URLS=$(curl -sk --max-time 10 "$HOST" 2>/dev/null | grep -oE 'src="[^"]+\.js[^"]*"' | sed 's/src="//;s/"$//' | head -30)
  for JS in $JS_URLS; do
    FULL_URL="$HOST/${JS#./}"
    echo "$JS" | grep -qE "^https?://" && FULL_URL="$JS"
    NAME=$(echo "$FULL_URL" | md5sum | cut -d' ' -f1)
    curl -sk --max-time 15 "$FULL_URL" -o "js_bundles/${PREFIX}_${NAME}.js" 2>/dev/null
    curl -sk --max-time 10 "${FULL_URL}.map" -o "js_bundles/${PREFIX}_${NAME}.js.map" 2>/dev/null
    [ -f "js_bundles/${PREFIX}_${NAME}.js" ] && {
      grep -oE '["'"'"'](/[a-z0-9/_-]+(?:/[a-z0-9_-]+){0,5})["'"'"']' "js_bundles/${PREFIX}_${NAME}.js" 2>/dev/null | tr -d '"'"'"'' | sort -u >> "endpoints_found/${PREFIX}.txt" 2>/dev/null
      grep -Eoh '[A-Za-z0-9_-]{32,}' "js_bundles/${PREFIX}_${NAME}.js" 2>/dev/null | grep -iE '^(sk_|pk_|ghp_|gho_|AIza|xox[abprs]|AKIA)' | sort -u >> "js_secrets/${PREFIX}.txt" 2>/dev/null
    }
  done
done < alive.txt
cat endpoints_found/*.txt 2>/dev/null | sort -u | head -2000 > js_endpoints.txt
cat js_secrets/*.txt 2>/dev/null | sort -u > js_secrets.txt
exit 0`, "grep", []string{"httpx_probe"}, 0},

		{"trufflehog_scan", "trufflehog filesystem clean_katana_urls.txt --only-verified > trufflehog_results.txt", "default", []string{"clean_urls"}, 0},

		// TIGHTER secrets regex: requires real key=value patterns (AKIA, ghp_,
		// Bearer, etc.) instead of any URL containing the word "secret".
		{"grep_secrets", `grep -Eih '(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{32,}|sk_live_[A-Za-z0-9]{24,}|AIza[0-9A-Za-z_-]{35}|ya29\.[0-9A-Za-z_-]{50,}|eyJ[A-Za-z0-9_=-]+\.eyJ[A-Za-z0-9_=-]+\.[A-Za-z0-9_.+/=-]+|Bearer\s+[A-Za-z0-9_-]{20,}|["'"'"']?api[_-]?key["'"'"']?\s*[:=]\s*["'"'"'][A-Za-z0-9_-]{16,}|["'"'"']?secret["'"'"']?\s*[:=]\s*["'"'"'][A-Za-z0-9_-]{16,}|["'"'"']?token["'"'"']?\s*[:=]\s*["'"'"'][A-Za-z0-9_-]{16,})' clean_katana_urls.txt | sort -u > potential_secrets.txt
# Also scan JS bundles for embedded secrets
[ -s js_bundles/ ] && grep -Eroh '(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{32,}|AIza[0-9A-Za-z_-]{35})' js_bundles/ 2>/dev/null | sort -u >> js_secrets.txt
exit 0`, "grep", []string{"clean_urls", "jsmap_scrape"}, 0},

		// gau_urls / wayback_urls: wrap in the shell `timeout` builtin so
		// even a wedged upstream API rate-limiter can't pin the stage
		// forever. `timeout --foreground` propagates SIGTERM cleanly;
		// without --foreground bash would background `timeout` and tee
		// would keep appending. We additionally cap the per-step budget
		// (Timeout field) at 10m to give the executor another layer of
		// defense if `timeout` itself is missing on the user's PATH
		// (rare — it's coreutils, present on every Linux we support).
		{"gau_urls", fmt.Sprintf("[ -s live_subs.txt ] && timeout --foreground %s cat live_subs.txt | gau --threads 5 --subs | tee gau_urls.txt || touch gau_urls.txt", urlMinerTimeout), "default", []string{"merge_brute_subs"}, 10 * time.Minute},
		{"wayback_urls", fmt.Sprintf("[ -s live_subs.txt ] && timeout --foreground %s cat live_subs.txt | waybackurls | tee wayback_urls.txt || touch wayback_urls.txt", urlMinerTimeout), "default", []string{"merge_brute_subs"}, 10 * time.Minute},
		{"merge_all_urls", "touch gau_urls.txt wayback_urls.txt clean_katana_urls.txt; cat gau_urls.txt wayback_urls.txt clean_katana_urls.txt | sort -u > all_urls.txt", "default", []string{"gau_urls", "wayback_urls", "clean_urls"}, 0},

		// URL dedup. all_urls.txt can balloon to 100k+ entries from
		// gau + wayback + katana; uro collapses the noise down to unique
		// endpoints so every downstream gf + nuclei stage runs faster.
		{"uro_dedup", "if command -v uro >/dev/null 2>&1; then uro < all_urls.txt > uro_urls.txt; cp uro_urls.txt all_urls.txt; else sort -u all_urls.txt -o all_urls.txt; fi", "grep", []string{"merge_all_urls"}, 0},

		// URL filter: now accepts 200, 301, 302, 401, 403, 405 — the
		// previous -mc 200 only filter dropped 8655 of 8740 URLs on
		// localwp.com because Cloudflare's bot detection returned 403.
		// 401/403/405 are testable endpoints requiring auth; 301/302 may
		// redirect to a testable path.
		{"url_filter_alive", "httpx -l all_urls.txt -silent -status-code -mc 200,301,302,401,403,405 -o all_urls_200.txt", "grep", []string{"uro_dedup"}, 0},

		// === NEW: Cleanup drop-reasons report (forensic) ===
		// === NEW: filter_testable_sqli. The cmd/filter-testable
		// wrapper takes `<workdir>` as its first arg; we run it from
		// inside the workDir (because of pipeline.go's cd-to-workdir
		// at executor.RunCommand time) and feed the file argument
		// via the relative path `all_urls_200.txt`.
		{"filter_testable_sqli", fmt.Sprintf(`%s . all_urls_200.txt > sqli_targets_filtered.txt
[ -s sqli_targets_filtered.txt ] && { gf sqli sqli_targets_filtered.txt >> sqli_targets.txt; grep -Ei '%s' sqli_targets_filtered.txt >> sqli_targets.txt; } || true
[ -s sqli_targets.txt ] && sort -u sqli_targets.txt -o sqli_targets.txt || touch sqli_targets.txt
[ -s sqli_targets.txt ] && head -n %d sqli_targets.txt > sqli_targets.txt.capped && mv sqli_targets.txt.capped sqli_targets.txt
exit 0`, filterTestableRef, sqlmapHighSignalParams, sqlmapTargetCap), "grep", []string{"url_filter_alive"}, 0},
		{"sqli_targets_replace", `[ -s sqli_targets.txt ] || cp sqli_targets_filtered.txt sqli_targets.txt 2>/dev/null
exit 0`, "grep", []string{"filter_testable_sqli"}, 0},

		// sqlmap_scan: now also passes auth headers via --cookie / --headers
		// AND the WAF tamper chosen by buildWafTamperSnippet() (which
		// reads waf_detections.txt). The `${WAF_SQLMAP_TAMPER:+...}`
		// expansion is empty when no WAF was detected — clean fallback.
		// Dependency on waf_detect is required so the tamper snippet
		// can read waf_detections.txt.
		{"sqlmap_scan", fmt.Sprintf(`%s
%s
[ -s sqli_targets.txt ] && timeout --foreground %s sqlmap -m <(head -n %d sqli_targets.txt) --batch --random-agent --flush-session --technique=BEUSTQ --level=3 --risk=1 --output-dir=./sqlmap_results $AUTH_SQLMAP ${WAF_SQLMAP_TAMPER:+--tamper=$WAF_SQLMAP_TAMPER} ; [ -d sqlmap_results ] || mkdir -p sqlmap_results ; true
exit 0`, buildAuthSqlmapCmd(), buildWafTamperSnippet(), sqlmapScanTimeout, sqlmapTargetCap), "default", []string{"sqli_targets_replace", "waf_detect"}, 15 * time.Minute},

		// xss_targets: filter for testable, then dedup, then cap
		{"xss_targets", fmt.Sprintf(`%s . all_urls_200.txt > xss_targets_filtered.txt
[ -s xss_targets_filtered.txt ] && grep -Ei "q=|search|query|keyword|text|name|email|msg|redirect|url=" xss_targets_filtered.txt > xss_targets.txt
gf xss xss_targets_filtered.txt >> xss_targets.txt 2>/dev/null || true
sort -u xss_targets.txt -o xss_targets.txt
[ -s xss_targets.txt ] && head -n %d xss_targets.txt > xss_targets.txt.capped && mv xss_targets.txt.capped xss_targets.txt
exit 0`, filterTestableRef, xssScanTargetCap), "grep", []string{"url_filter_alive"}, 0},

		// xss_scan: also threads the WAF-detected tamper into dalfox via
		// `--bypass=$WAF_DALFOX_BYPASS`. Empty when no WAF. Dependency on
		// waf_detect added so the buildWafTamperSnippet() output (which
		// reads waf_detections.txt) sees the file written.
		{"xss_scan", fmt.Sprintf(`%s
%s
head -n %d xss_targets.txt > xss_targets_capped.txt
[ -s xss_targets_capped.txt ] && timeout --foreground %s bash -c 'cat xss_targets_capped.txt | Gxss -p khXSS | dalfox pipe --mining-dom -o xss_vulnerabilities.txt ${WAF_DALFOX_BYPASS:+--bypass=$WAF_DALFOX_BYPASS}'
touch xss_vulnerabilities.txt
exit 0`, authSnip, buildWafTamperSnippet(), xssScanTargetCap, xssScanTimeout), "default", []string{"xss_targets", "waf_detect"}, 10 * time.Minute},

		// rce_targets: filter + dedup + cap
		{"rce_targets", fmt.Sprintf(`%s . all_urls_200.txt > rce_targets_filtered.txt
{ gf rce rce_targets_filtered.txt; grep -Ei '[?&](cmd|exec|command|ping|daemon|upload|shell|code)=' rce_targets_filtered.txt; } | sort -u | head -n %d > rce_targets.txt
exit 0`, filterTestableRef, maxScanTargets), "grep", []string{"url_filter_alive"}, 0},
		{"rce_scan", fmt.Sprintf("nuclei -l rce_targets.txt -tags rce -severity high,critical %s -o nuclei_rce_rce.txt", nucleiOptimized), "default", []string{"rce_targets"}, 0},

		// idor_targets: filter out Discourse public forum URLs (these are
		// public read-only and can't have IDOR). Same filter logic.
		{"idor_targets", fmt.Sprintf(`%s . all_urls_200.txt > idor_targets_filtered.txt
{ gf idor idor_targets_filtered.txt; grep -Ei '[?&](id|account|order|doc|profile|booking|reservation|uid|user_id)=' idor_targets_filtered.txt; } | sort -u | head -n %d > idor_targets.txt
exit 0`, filterTestableRef, maxScanTargets), "grep", []string{"url_filter_alive"}, 0},
		{"idor_scan", fmt.Sprintf("nuclei -l idor_targets.txt -tags idor %s -o idor_vulnerabilities.txt", nucleiOptimized), "default", []string{"idor_targets"}, 0},

		// ssrf_targets: filter + dedup
		{"ssrf_targets", fmt.Sprintf(`%s . all_urls_200.txt > ssrf_targets_filtered.txt
{ gf ssrf ssrf_targets_filtered.txt; grep -Ei "url=|uri=|path=|dest=|redirect=|callback=|webhook=|src=|fetch=|proxy=|target=" ssrf_targets_filtered.txt; } | sort -u > ssrf_targets.txt
exit 0`, filterTestableRef), "grep", []string{"url_filter_alive"}, 0},
		// ssrf_scan: substitute ${OOB}->interactsh URL for blind SSRF detection
		{"ssrf_scan", fmt.Sprintf(`if [ -n "$RFUF_OOB_URL" ]; then
  sed "s|FOOBAR|$RFUF_OOB_URL|g" ssrf_targets.txt > ssrf_targets_oob.txt
  nuclei -l ssrf_targets_oob.txt -tags ssrf %s -o ssrf_vulnerabilities.txt -var oob_url=$RFUF_OOB_URL
else
  nuclei -l ssrf_targets.txt -tags ssrf %s -o ssrf_vulnerabilities.txt
fi
exit 0`, nucleotidesOptimizedAuth(), nucleiOptimized), "default", []string{"ssrf_targets"}, 0},

		// redirect_targets: filter + dedup + cap
		{"redirect_targets", fmt.Sprintf(`%s . all_urls_200.txt > redirect_targets_filtered.txt
gf redirect redirect_targets_filtered.txt | sort -u | head -n %d > redirect_targets.txt
exit 0`, filterTestableRef, maxScanTargets), "grep", []string{"url_filter_alive"}, 0},
		{"redirect_scan", fmt.Sprintf("nuclei -l redirect_targets.txt -tags redirect %s -o open_redirect_results.txt", nucleiOptimized), "default", []string{"redirect_targets"}, 0},

		// lfi_targets: filter + dedup
		{"lfi_targets", fmt.Sprintf(`%s . all_urls_200.txt > lfi_targets_filtered.txt
gf lfi lfi_targets_filtered.txt > lfi_targets.txt
sort -u lfi_targets.txt -o lfi_targets.txt
exit 0`, filterTestableRef), "grep", []string{"url_filter_alive"}, 0},
		{"lfi_scan", fmt.Sprintf("nuclei -l lfi_targets.txt -tags lfi %s -o lfi_results.txt", nucleiOptimized), "default", []string{"lfi_targets"}, 0},

		// cors_check: now credentialed — checks both ACAO and ACAC.
		{"cors_check", `set +e
head -n 500 alive.txt | xargs -P 20 -I{} sh -c '
  ORIGIN="https://evil.com"
  RESP=$(curl -sk --max-time 5 --connect-timeout 3 -H "Origin: $ORIGIN" -H "Access-Control-Request-Credentials: true" -I "{}" 2>/dev/null)
  ACAO=$(echo "$RESP" | grep -i "^access-control-allow-origin:" | tr -d "\r" | awk "{print \$2}")
  ACAC=$(echo "$RESP" | grep -i "^access-control-allow-credentials:" | tr -d "\r" | awk "{print \$2}")
  if [ -n "$ACAO" ] && [ "$ACAO" != "$ORIGIN" ]; then
    if [ "$ACAO" = "*" ] || [ "$ACAO" = "null" ]; then
      [ "$ACAC" = "true" ] && echo "[VULN] {}  ACAO=$ACAO ACAC=$ACAC (credentialed)"
    fi
  elif [ "$ACAO" = "$ORIGIN" ]; then
    [ "$ACAC" = "true" ] && echo "[VULN] {}  ACAO=REFLECTED ACAC=$ACAC (credentialed exfil)"
  fi
' 2>/dev/null > cors_findings.txt
exit 0`, "grep", []string{"httpx_probe"}, 0},

		// ffuf: recursion depth 1 (was 2), broader status match, more permissive timeout.
		{"dirbrute_ffuf", fmt.Sprintf(`mkdir -p ffuf_results
if [ -n "%s" ] && [ -s alive.txt ]; then
  ffuf -w alive.txt:HOST -w %s:WORD -u "HOST/WORD" -mc 200,201,204,301,302,307,308,401,403,405 -ac -t 30 -maxtime 1200 -recursion -recursion-depth 1 -o ffuf_results/all.json -of json -s
  jq -r '.results[]? | .url' ffuf_results/all.json 2>/dev/null | sort -u > ffuf_dirs_raw.txt
else
  : > ffuf_dirs_raw.txt
fi
exit 0`, wordlist, wordlist), "default", []string{"httpx_probe"}, 0},

		// 200-only verification of ffuf hits.
		{"dirbrute_verify_200", "if [ -s ffuf_dirs_raw.txt ]; then httpx -l ffuf_dirs_raw.txt -silent -status-code -mc 200 -o ffuf_dirs_200.txt; else : > ffuf_dirs_200.txt; fi", "grep", []string{"dirbrute_ffuf"}, 0},

		// NEW: scan JS-discovered endpoints against nuclei token-spray/misconfig
		{"js_endpoints_scan", fmt.Sprintf("nuclei -l js_endpoints.txt -tags exposure,token-spray,misconfig %s -o js_endpoint_findings.txt", nucleiOptimized), "default", []string{"jsmap_scrape"}, 0},

		{"manual_review_queue", "grep -Ei \"checkout|price|payment|coupon|book|cart|fare\" all_urls.txt | sort -u > manual_business_logic_review.txt", "grep", []string{"merge_all_urls"}, 0},

		// === Modern methodology additions (bb-methodology + security-arsenal) ===
		// waf_detect: cap to 200 hosts to keep wafw00f runtime bounded.
		// wafw00f issues one HTTP request per host; at 5k hosts with default
		// socket timeouts this becomes a 30-min+ serial scan. 200 hosts is
		// enough to fingerprint the WAF vendor(s) in the target's infrastructure.
		{"waf_detect", "if command -v wafw00f >/dev/null 2>&1; then head -n 200 alive.txt > waf_targets_tmp.txt; wafw00f -i waf_targets_tmp.txt -o waf_detections.txt || true; rm -f waf_targets_tmp.txt; else : > waf_detections.txt; fi", "grep", []string{"httpx_probe"}, 0},
		{"port_scan_naabu", "if command -v naabu >/dev/null 2>&1; then naabu -list alive.txt -top-ports 1000 -rate 1000 -silent -o naabu_ports.txt || true; else : > naabu_ports.txt; fi", "grep", []string{"httpx_probe"}, 0},

		// Hidden parameter discovery (arjun). Cap to 100 hosts — arjun's
		// batch mode sends many requests per host; beyond 100 the runtime
		// easily exceeds the step timeout and yields diminishing returns.
		{"hidden_params_arjun", "if command -v arjun >/dev/null 2>&1 && [ -s alive.txt ]; then head -n 100 alive.txt > arjun_targets_tmp.txt; arjun -i arjun_targets_tmp.txt -oT hidden_params.txt -t 10 --rate-limit 10 || touch hidden_params.txt; rm -f arjun_targets_tmp.txt; else : > hidden_params.txt; fi", "grep", []string{"httpx_probe"}, 0},

		// Modern blind SQLi.
		{"ghauri_sqli", "if command -v ghauri >/dev/null 2>&1; then { head -n 200 sqli_targets.txt; grep -Ei '[?&](id|uid|order|product|category|page|article|comment|msg)=' sqli_targets.txt; } | sort -u | head -n 100 > ghauri_targets.txt; [ -s ghauri_targets.txt ] && ghauri -m ghauri_targets.txt --batch --level=2 --risk=1 --technique=BT -o ghauri_results.txt || true; else : > ghauri_results.txt; fi", "grep", []string{"sqli_targets_replace"}, 0},

		// ===================================================================
		// === Phase 1: Wire up the 10 unwritten-into-pipeline finders =====
		// ===================================================================
		//
		// Each is a `go run ./cmd/findings-runner <name> .` invocation.
		// The dot is the workdir — every stage runs from paths.WorkDir
		// because executor.RunCommand sets cmd.Dir = workDir.

		// Reflection finder: classify every URL's query param into
		// html-body / attr-quoted / attr-unquoted / json-value. The
		// result feeds dalfox with already-confirmed reflection sites
		// (no need for dalfox to guess). Depends on url_filter_alive
		// because we probe all_urls_200.txt.
		{"reflection_run", fmt.Sprintf(`%s reflection . || true
exit 0`, findingsRunnerRef), "grep", []string{"url_filter_alive"}, 0},

		// ParamShape (HTTP Parameter Pollution). Probes candidate
		// object-reference params with 5 distinct shapes (?id=1,
		// ?id[]=1, ?id=1&id=2, mixed case, null byte) and reports
		// when the response hashes diverge. Depends on httpx_probe
		// because it works off alive.txt.
		{"paramshape_run", fmt.Sprintf(`%s paramshape . || true
exit 0`, findingsRunnerRef), "grep", []string{"httpx_probe"}, 0},

		// AuthShape (cookie + JWT misconfig). Per-host probe of
		// Set-Cookie / Authorization. Flags missing HttpOnly/Secure/
		// SameSite, alg:none JWTs, missing exp claim. Depends on
		// httpx_probe (needs alive.txt).
		{"authshape_run", fmt.Sprintf(`%s authshape . || true
exit 0`, findingsRunnerRef), "grep", []string{"httpx_probe"}, 0},

		// Signup-takeover fingerprinting. Probes /signup, /register,
		// /api/users, etc. for email-verify URL patterns and tokens
		// in the response. Depends on httpx_probe.
		{"signup_takeover_run", fmt.Sprintf(`%s signup . || true
exit 0`, findingsRunnerRef), "grep", []string{"httpx_probe"}, 0},

		// IDOR surface mapping. Per-parameter roll-up of how many
		// hosts use each object-reference param and how many distinct
		// IDs were observed. The hunter uses this to set up two
		// accounts and test the top-N params for IDOR.
		{"idor_surface_run", fmt.Sprintf(`%s idor . || true
exit 0`, findingsRunnerRef), "grep", []string{"merge_all_urls"}, 0},

		// OAuth redirect_uri bypass audit. Per-host probe of
		// authorize endpoints + .well-known/openid-configuration.
		// Emits 5 bypass-class payloads per allowlist entry as
		// ready-to-curl commands. Manual retest only.
		{"oauth_audit_run", fmt.Sprintf(`%s oauth . || true
exit 0`, findingsRunnerRef), "grep", []string{"httpx_probe"}, 0},

		// Race-condition surface + 20-way concurrent probe of the
		// top-25 candidates. Depends on merge_all_urls so coupon/
		// transfer/withdraw URLs from wayback + katana are in scope.
		{"race_scan", fmt.Sprintf(`%s race . || true
exit 0`, findingsRunnerRef), "grep", []string{"merge_all_urls"}, 0},

		// Bucket-guess takeover. Reads tech_fingerprint + alive.txt
		// for org-name candidates; HEAD-tests s3/gcs/azure URLs.
		{"bucket_guess_run", fmt.Sprintf(`%s buckets . || true
exit 0`, findingsRunnerRef), "grep", []string{"tech_fingerprint"}, 0},

		// Per-service takeover fingerprint (Vercel/Netlify/Fly/
		// AzSWA). Probes every DNS-resolving host for the canonical
		// 404 page strings. Depends on httpx_probe so DNS-resolving
		// hosts from live_subs.txt are available.
		{"takeover_v2_run", fmt.Sprintf(`%s takeoversvc . || true
exit 0`, findingsRunnerRef), "grep", []string{"httpx_probe"}, 0},

		// Deep JS bundle mining. Reads js_bundles/, extracts secrets,
		// POST endpoints, admin paths, S3 URLs, GraphQL mutation
		// names. Depends on jsmap_scrape which populates js_bundles/.
		{"js_mine_run", fmt.Sprintf(`%s jsmine . || true
exit 0`, findingsRunnerRef), "grep", []string{"jsmap_scrape"}, 0},

		// ===================================================================
		// === Phase 2: New finder modules ==================================
		// ===================================================================

		// Security headers analysis. Per-host probe of CSP, HSTS,
		// X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
		// Permissions-Policy, COOP/COEP/CORP. Missing CSP = reportable
		// (XSS-class). Depends on httpx_probe.
		{"secheaders_run", fmt.Sprintf(`%s secheaders . || true
exit 0`, findingsRunnerRef), "grep", []string{"httpx_probe"}, 0},

		// Backup / sensitive-file probing. Single highest-yield bug
		// class: exposed .env, .git/config, wp-config.php.bak, db.sql,
		// id_rsa, aws-credentials, etc. Depends on tech_fingerprint
		// (so we know which stack-specific paths to add) and httpx_probe.
		{"backupscan_run", fmt.Sprintf(`%s backupscan . || true
exit 0`, findingsRunnerRef), "grep", []string{"tech_fingerprint"}, 0},

		// Business-logic surface mapping. Categorizes URLs containing
		// pricing/coupon/balance/vote/gift/payment/currency keywords
		// into severity groups; flags suspicious query-param shapes
		// (quantity=, price=, coupon=, currency=, role=, admin=).
		// Depends on merge_all_urls.
		{"businesslogic_run", fmt.Sprintf(`%s businesslogic . || true
exit 0`, findingsRunnerRef), "grep", []string{"merge_all_urls"}, 0},

		// Host-header injection probe. Sends requests with attacker-
		// controlled Host / X-Forwarded-Host / X-Original-URL / X-Host
		// values and inspects the response for marker reflection.
		// Catches password-reset poisoning, cache poisoning, SSRF,
		// open-redirect chains.
		{"hostheader_run", fmt.Sprintf(`%s hostheader . || true
exit 0`, findingsRunnerRef), "grep", []string{"httpx_probe"}, 0},

		// Credentialed CORS preflight check. Tests OPTIONS preflight
		// + null-origin cases that the inline bash cors_check misses.
		{"cors2_run", fmt.Sprintf(`%s cors2 . || true
exit 0`, findingsRunnerRef), "grep", []string{"httpx_probe"}, 0},

		// ===================================================================
		// === Phase 3: Custom nuclei template pass ========================
		// ===================================================================
		//
		// The bundled nuclei-templates-rfuf/ overlay targets high-signal
		// bug classes the default nuclei tags miss:
		//   - debug endpoints (.env, phpinfo, server-status, ...)
		//   - SaaS API tokens in HTML (Intercom, Mixpanel, Datadog, ...)
		//   - JWT alg:none reflection
		//   - host header injection via X-Forwarded-Host
		//   - credentialed CORS preflight
		//   - null-origin reflected with credentials
		// Runs last so all preceding stages have populated alive.txt +
		// tech_fingerprint.txt. Capped to ~5 templates × alive.txt hosts
		// → bounded runtime.
		{"nuclei_rfuf_pass", fmt.Sprintf("nuclei -l alive.txt -t nuclei-templates-rfuf/ %s -o nuclei_rfuf_pass.txt", nucleiOptimized), "grep", []string{"httpx_probe"}, 0},
	}
}

// buildAuthSqlmapCmd returns a shell preamble that translates RFUF_AUTH_*
// env vars into sqlmap-compatible --cookie / --headers flags. The
// resulting string is intended to be the first line of a multi-line
// `sqlmap_scan` command that uses bash variable expansion to inject auth.
func buildAuthSqlmapCmd() string {
	return `
AUTH_SQLMAP=""
[ -n "$RFUF_AUTH_COOKIE" ] && AUTH_SQLMAP="$AUTH_SQLMAP --cookie=$RFUF_AUTH_COOKIE"
[ -n "$RFUF_AUTH_HEADER" ] && AUTH_SQLMAP="$AUTH_SQLMAP --headers=Authorization: $RFUF_AUTH_HEADER"
`
}

// nucleotidesOptimizedAuth returns the nuclei args including -H flags if
// auth is set. Used by SSRF scan (and similar) where we want different
// command-line shapes than the default nucleiOptimized constant.
func nucleotidesOptimizedAuth() string {
	// Note: this is a placeholder for the second-pass nuclei auth wiring.
	// The current implementation relies on the env-vars-only mechanism
	// (i.e. nuclie reads RFUF_AUTH_HEADER via -H interpolation in the
	// shell). A future refactor could thread -H directly through nuclei.
	return " -rl 300 -c 50 -bs 25 -timeout 5 -retries 1 -silent -stats -stats-interval 30"
}

// buildWafTamperSnippet returns a shell preamble that resolves to the
// right tamper flags for the detected WAF. Reads waf_detections.txt
// at the start of the stage to pick the per-vendor tamper; sets
// WAF_SQLMAP_TAMPER, WAF_DALFOX_BYPASS, WAF_VENDOR env vars. Stages
// that already issue sqlmap / dalfox / nuclei scan commands
// interpolate these as `${WAF_SQLMAP_TAMPER:+--tamper=$WAF_SQLMAP_TAMPER}`.
//
// The implementation reads waf_detections.txt with a simple awk pass
// rather than shelling out to the Go wafbypass helper — every other
// stage in this file is a bash one-liner and we want the WAF detection
// to fit in the same model. The Go package is available for any
// finding module that needs catalog values directly.
func buildWafTamperSnippet() string {
	return `
if [ -s waf_detections.txt ]; then
  if grep -qi "cloudflare" waf_detections.txt; then
    WAF_VENDOR="cloudflare"
    WAF_SQLMAP_TAMPER="between,randomcase,space2comment"
    WAF_DALFOX_BYPASS="wasm"
  elif grep -qi "imperva" waf_detections.txt; then
    WAF_VENDOR="imperva"
    WAF_SQLMAP_TAMPER="randomcase,between,space2comment"
    WAF_DALFOX_BYPASS="html"
  elif grep -qi "akamai" waf_detections.txt; then
    WAF_VENDOR="akamai"
    WAF_SQLMAP_TAMPER="randomcase,between,space2comment,versionedkeywords"
    WAF_DALFOX_BYPASS="html"
  elif grep -qi "aws\|cloudfront" waf_detections.txt; then
    WAF_VENDOR="aws"
    WAF_SQLMAP_TAMPER="randomcase,space2plus"
    WAF_DALFOX_BYPASS="utf-8"
  elif grep -qi "fastly" waf_detections.txt; then
    WAF_VENDOR="fastly"
    WAF_SQLMAP_TAMPER="between,randomcase"
    WAF_DALFOX_BYPASS="utf-8"
  elif grep -qi "f5" waf_detections.txt; then
    WAF_VENDOR="f5"
    WAF_SQLMAP_TAMPER="space2mysqldash,randomcase,between"
    WAF_DALFOX_BYPASS="unicode"
  elif grep -qi "barracuda" waf_detections.txt; then
    WAF_VENDOR="barracuda"
    WAF_SQLMAP_TAMPER="space2mysqldash,randomcase,unionalltounion"
    WAF_DALFOX_BYPASS="html"
  elif grep -qi "sucuri" waf_detections.txt; then
    WAF_VENDOR="sucuri"
    WAF_SQLMAP_TAMPER="between,randomcase,space2comment,modsecurityversioned"
    WAF_DALFOX_BYPASS="html"
  elif grep -qE "waf|firewall" waf_detections.txt; then
    WAF_VENDOR="generic"
    WAF_SQLMAP_TAMPER="between"
    WAF_DALFOX_BYPASS="html"
  else
    WAF_VENDOR=""
    WAF_SQLMAP_TAMPER=""
    WAF_DALFOX_BYPASS=""
  fi
else
  WAF_VENDOR=""
  WAF_SQLMAP_TAMPER=""
  WAF_DALFOX_BYPASS=""
fi
export WAF_VENDOR WAF_SQLMAP_TAMPER WAF_DALFOX_BYPASS
`
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

					res, err := executor.RunCommand(ctx, step.Command, paths.WorkDir, logFile, effectiveStepTimeout(stepTimeout, step.Timeout))

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
