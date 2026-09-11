package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/CyberShuriken/rfuf/internal/checkpoint"
	"github.com/CyberShuriken/rfuf/internal/cli"
	"github.com/CyberShuriken/rfuf/internal/config"
	"github.com/CyberShuriken/rfuf/internal/coverage"
	"github.com/CyberShuriken/rfuf/internal/evidence"
	"github.com/CyberShuriken/rfuf/internal/executor"
	"github.com/CyberShuriken/rfuf/internal/owasp"
	"github.com/CyberShuriken/rfuf/internal/scope"
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

	// softStages are discovery or merge steps that can legitimately return
	// zero results or time out without failing the whole pipeline.
	softStages = map[string]bool{
		"scope_guard":          true,
		"amass_enum":           true,
		"subfinder":            true,
		"assetfinder":         true,
		"jsmap_scrape":         true,
		"hidden_params_arjun":  true,
		"katana_crawl":         true,
		"merge_brute_subs":     true,
		"merge_js_endpoints":   true,
		"dirbrute_ffuf":        true,
		"gau_urls":             true,
		"wayback_urls":         true,
		"sqlmap_scan":          true,
		"xss_scan":             true,
		"nuclei_exposures":     true,
		"nuclei_misconfigs":    true,
		"nuclei_auth_scan":     true,
		"nuclei_graphql_scan":   true,
		"nuclei_rfuf_pass":     true,
	}

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
	nucleiOptimized = " -rl ${RFUF_MAX_STAGE_REQUESTS:-300} -c 50 -bs 25 -timeout 5 -retries 1 -silent -stats -stats-interval 30"

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

	// JS collection is intentionally bounded per host and globally. Modern
	// SPAs can reference hundreds of chunks; an unbounded collector turns
	// one wildcard into an accidental asset mirror.
	jsAssetTotalCap     = 5000
	nucleiTargetCap     = 10000
	katanaTargetCap     = 200
	katanaCrawlDuration = "10m"
	katanaStepTimeout   = 12 * time.Minute
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
//	AUTH_HEADERS=$(buildAuthHeaderSnippet_shell)
//	httpx -l alive.txt "${AUTH_HEADERS[@]}" ...
//
// Implemented as a shell function in the stage command's preamble so each
// tool can `${AUTH_HEADERS:+...}` for backward compat.
func buildAuthHeaderSnippet() string {
	return `
AUTH_HEADERS=()
[ -n "$RFUF_AUTH_COOKIE" ] && AUTH_HEADERS+=(-H "Cookie: $RFUF_AUTH_COOKIE")
[ -n "$RFUF_AUTH_HEADER" ] && AUTH_HEADERS+=(-H "Authorization: $RFUF_AUTH_HEADER")
[ -n "$RFUF_BUG_BOUNTY_USERNAME" ] && AUTH_HEADERS+=(-H "X-Bug-Bounty: $RFUF_BUG_BOUNTY_USERNAME" -H "X-HackerOne-Research: $RFUF_BUG_BOUNTY_USERNAME")
[ -n "$RFUF_TEST_ACCOUNT_EMAIL" ] && AUTH_HEADERS+=(-H "X-Test-Account-Email: $RFUF_TEST_ACCOUNT_EMAIL")
`
}

// GetSteps returns the ordered list of pipeline stages. Each entry is a
// self-contained bash one-liner that the executor runs. The stages are
// grouped by phase:
//
//	Phase 1 — Recon            (subfinder, assetfinder, amass, dnsx, brute)
//	Phase 2 — Probing          (httpx, tech fingerprint, takeover, waf, ports)
//	Phase 3 — Tech-specific    (Discourse, Laravel, WordPress, cache-poison)
//	Phase 4 — URL mining       (katana, gau, wayback, jsmap scrape)
//	Phase 5 — Secret scanning  (trufflehog, grep)
//	Phase 6 — Host enumeration (URL filter, target lists, vuln scans)
//	Phase 7 — Reconnaissance   (cors, ffuf, hidden params, manual review)
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
	parsed, err := scope.Parse(domain)
	if err != nil {
		parsed = scope.Scope{Input: domain, RootDomain: domain, Mode: scope.ExactMode}
	}
	return GetStepsForScope(parsed, paths)
}

func GetStepsForScope(scanScope scope.Scope, paths *config.Paths) []Step {
	domain := scanScope.RootDomain
	domainEscaped := strings.ReplaceAll(domain, ".", "\\.")
	wordlist := pickWordlist(paths)
	authSnip := buildAuthHeaderSnippet()
	wildcardPattern := fmt.Sprintf(`^https?://([^/]+\.)?%s(/|$|[[:space:]])`, domainEscaped)
	if scanScope.Mode == scope.ExactMode {
		wildcardPattern = fmt.Sprintf(`^https?://%s(/|$|[[:space:]])`, domainEscaped)
	}

	// Discovery helper: skip expensive scans in exact mode
	disc := func(id, fullCmd, out string) string {
		if scanScope.Mode == scope.ExactMode {
			return fmt.Sprintf("echo %s > %s", domain, out)
		}
		return fullCmd
	}

	// oobSubstitute is a one-liner that writes a target file with
	// ${OOB} placeholders expanded to the actual interactsh URL. Used by
	// SSRF/RCE/XSS stages to inject blind-callback URLs.
	oobSubstitute := func(in, out string) string {
		return fmt.Sprintf("sed 's|${OOB}|%s|g' %s > %s", "${RFUF_OOB_URL}", in, out)
	}

	_ = oobSubstitute // used via inline references in commands below

	subdomainBruteCmd := "exit 0"
	if scanScope.Mode != scope.ExactMode {
		subdomainBruteCmd = fmt.Sprintf(`set +e
: > brute_subs.txt
if [ "$RFUF_SCOPE_MODE" != "wildcard" ]; then
  exit 0
fi
if [ -s "%s" ]; then
  sed "s|$|.%s|" "%s" | dnsx -silent -o brute_subs.txt
fi
sort -u brute_subs.txt -o brute_subs.txt
exit 0`, wordlist, domain, wordlist)
	}

	return []Step{
		{"setup_directories", fmt.Sprintf("mkdir -p %s", paths.WorkDir), "default", nil, 0},
		{"subfinder", disc("subfinder", fmt.Sprintf("subfinder -d %s -all -o subfinder.txt", domain), "subfinder.txt"), "default", []string{"setup_directories"}, 0},
		{"assetfinder", disc("assetfinder", fmt.Sprintf("assetfinder --subs-only %s > assetfinder.txt", domain), "assetfinder.txt"), "default", []string{"setup_directories"}, 0},
		{"amass_enum", disc("amass_enum", fmt.Sprintf("if ! timeout --foreground 10m amass enum -passive -norecursive -timeout 30 -d %s -o amass_raw.txt; then echo '[!] Amass enumeration failed; continuing with other sources' >/dev/null; fi; [ -f amass_raw.txt ] || touch amass_raw.txt", domain), "amass_raw.txt"), "default", []string{"setup_directories"}, 0},
		{"amass_parse", disc("amass_parse", fmt.Sprintf("[ -f amass_raw.txt ] && grep -F \"%s\" amass_raw.txt | sort -u > amass_sub.txt || touch amass_sub.txt", domain), "amass_sub.txt"), "grep", []string{"amass_enum"}, 0},
		{"merge_subs", "touch subfinder.txt assetfinder.txt amass_sub.txt; cat subfinder.txt assetfinder.txt amass_sub.txt | sort -u > subs.txt", "default", []string{"subfinder", "assetfinder", "amass_parse"}, 0},
		{"scope_guard", `set +e
ROOT=$(printf '%s' "$RFUF_DOMAIN" | tr '[:upper:]' '[:lower:]' | sed 's/\.$//')
[ -f subs.txt ] || : > subs.txt
WILDCARD=0
[ "$RFUF_SCOPE_MODE" = "wildcard" ] && WILDCARD=1
: > in_scope_hosts.txt
: > out_of_scope_hosts.txt
awk -v root="$ROOT" -v wildcard="$WILDCARD" '
  function lower(s) { return tolower(s) }
  {
    host=lower($0); sub(/\.$/, "", host)
    if (host == root || (wildcard == 1 && length(host) > length(root)+1 && substr(host, length(host)-length(root), length(root)+1) == "." root)) print host > "in_scope_hosts.txt"
    else print $0 > "out_of_scope_hosts.txt"
  }
' subs.txt || :
sort -u in_scope_hosts.txt -o in_scope_hosts.txt 2>/dev/null || :
sort -u out_of_scope_hosts.txt -o out_of_scope_hosts.txt 2>/dev/null || :
if [ "$WILDCARD" = "0" ] && [ $(wc -l < out_of_scope_hosts.txt 2>/dev/null || echo 0) -gt 10 ]; then
  echo "[!] Warning: You are in EXACT mode. $(wc -l < out_of_scope_hosts.txt) subdomains were filtered out. Use --wildcard to scan them." >&2
fi
: > scoped_subs.txt
cat in_scope_hosts.txt > scoped_subs.txt 2>/dev/null || :
IN=$(wc -l < scoped_subs.txt | tr -d ' ')
OUT=$(wc -l < out_of_scope_hosts.txt | tr -d ' ')
printf '{"input":"%s","root_domain":"%s","mode":"%s","in_scope":%s,"out_of_scope":%s,"policy":"%s"}
' "$RFUF_SCOPE_INPUT" "$ROOT" "$RFUF_SCOPE_MODE" "${IN:-0}" "${OUT:-0}" "$RFUF_SCOPE_MODE" > scope.json
touch scope.json in_scope_hosts.txt out_of_scope_hosts.txt scoped_subs.txt`, "default", []string{"merge_subs"}, 0},
		{"dnsx_resolve", "dnsx -l scoped_subs.txt -silent -o live_subs.txt", "default", []string{"scope_guard"}, 0},
		{"subdomain_brute", subdomainBruteCmd, "grep", []string{"dnsx_resolve"}, 0},
		{"merge_brute_subs", "cat scoped_subs.txt brute_subs.txt | sort -u > subs_with_brute.txt && mv subs_with_brute.txt live_subs.txt", "default", []string{"subdomain_brute"}, 0},
		{"httpx_probe", fmt.Sprintf("%s\nhttpx -l live_subs.txt -silent -status-code -title -tech-detect -o alive.txt", authSnip), "default", []string{"merge_brute_subs"}, 0},
		{"tech_fingerprint", "httpx -l alive.txt -silent -tech-detect -o tech_fingerprint.txt", "default", []string{"httpx_probe"}, 0},
		{"api_discovery", fmt.Sprintf(`set +e
mkdir -p api_specs
fetch_spec() {
  HOST=$1
  SAFE_HOST=$(echo "$HOST" | sed 's|https\?://||;s|[:/.]|_|g')
  for PATH in /openapi.json /swagger.json /api/openapi.json /api/swagger.json /sitemap.xml /robots.txt /.well-known/openid-configuration; do
    URL="${HOST}${PATH}"
    if curl -sk --max-time 5 -o "${SAFE_HOST}$(echo $PATH | sed 's|^/||;s|/|_|g').json" "$URL" && [ -s "${SAFE_HOST}$(echo $PATH | sed 's|^/||;s|/|_|g').json" ]; then
      echo "[+] Found spec: $URL"
    fi
  done
}
export -f fetch_spec
cat alive.txt | xargs -P 10 -I{} bash -c 'fetch_spec "{}"'
exit 0`, authSnip), "default", []string{"httpx_probe"}, 0},
		{"jsmap_scrape", fmt.Sprintf(`set +e
resolve_asset() {
  REF="$1"; BASE="$2"
  case "$REF" in
    https://*|http://*) printf '%%s\\n' "$REF" ;;
    //* ) printf 'https:%%s\\n' "$REF" ;;
    /* ) printf '%%s%%s\\n' "$(echo "$BASE" | sed 's|\\(https\\?://[^/]*\\).*|\\1|')" "$REF" ;;
    * ) printf '%%s/%%s\\n' "${BASE%%/}" "${REF#./}" ;;
  esac
}
while read -r HOST; do
  [ -n "$HOST" ] || continue
  PREFIX=$(echo "$HOST" | sed 's|https\\?://||;s|[^A-Za-z0-9._-]|_|g')
  PAGE="js_bundles/${PREFIX}_page.html"
  fetch_asset "$HOST" "$PAGE" || true
  {
    grep -oE 'src="[^"]+"|href="[^"]+"' "$PAGE" 2>/dev/null | sed -E 's/^[^=]+="//;s/"$//'
    grep -oE "src='[^']+'|href='[^']+'" "$PAGE" 2>/dev/null | sed -E "s/^[^=]+='//;s/'$//"
    printf '%%s\\n' /manifest.json /asset-manifest.json /manifest.webmanifest /build-manifest.json /routes-manifest.json /_next/build-manifest.json /_next/static/chunks/webpack.js /static/js/main.js
  } | while read -r REF; do
    [ -n "$REF" ] || continue
    FULL=$(resolve_asset "$REF" "$HOST")
    echo "$FULL" | grep -Eiq '\\.(js|mjs|map|json|webmanifest)([?#].*)?$|/(manifest|asset-manifest|build-manifest|routes-manifest)(\\.json)?([?#].*)?$|/_next/static/' || continue
    echo "$FULL" >> js_assets.txt
  done
done < alive.txt
sort -u js_assets.txt -o js_assets.txt
head -n %d js_assets.txt > js_assets.capped && mv js_assets.capped js_assets.txt
while read -r FULL_URL; do
  [ -n "$FULL_URL" ] || continue
  PREFIX=$(echo "$FULL_URL" | sed 's|https\\?://||;s|[^A-Za-z0-9._-]|_|g')
  NAME=$(printf '%%s' "$FULL_URL" | md5sum | cut -d' ' -f1)
  OUT="js_bundles/${PREFIX}_${NAME}.js"
  echo "$FULL_URL" | grep -Eiq '\\.(json|webmanifest)([?#].*)?$|manifest|buildManifest' && OUT="js_bundles/${PREFIX}_${NAME}.json"
  fetch_asset "$FULL_URL" "$OUT" || { echo "$FULL_URL" >> js_asset_errors.txt; continue; }
  [ -s "$OUT" ] || continue
  HOST_BASE=$(echo "$FULL_URL" | sed 's|\\(https\\?://[^/]*\\).*|\\1|')
  {
    grep -oE '"(/[A-Za-z0-9_./?&=-]+)"' "$OUT" 2>/dev/null | tr -d '"'
    grep -oE "'/[A-Za-z0-9_./?&=-]+'" "$OUT" 2>/dev/null | tr -d "'"
  } | while read -r PATH_CAND; do
    case "$PATH_CAND" in /*) echo "$HOST_BASE$PATH_CAND" ;; esac
  done >> "endpoints_found/${PREFIX}.txt"
  grep -Eoh '(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk-(test_|live_)?[A-Za-z0-9]{24,}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_=-]+\.eyJ[A-Za-z0-9_=-]+\.[A-Za-z0-9_.+/=-]+)' "$OUT" 2>/dev/null | sort -u >> "js_secrets/${PREFIX}.txt"
done < js_assets.txt
cat endpoints_found/*.txt 2>/dev/null | sort -u | head -2000 > js_endpoints.txt
cat js_secrets/*.txt 2>/dev/null | sort -u > js_secrets.txt
printf 'assets=%%s errors=%%s endpoints=%%s\\n' "$(wc -l < js_assets.txt 2>/dev/null || echo 0)" "$(wc -l < js_asset_errors.txt 2>/dev/null || echo 0)" "$(wc -l < js_endpoints.txt 2>/dev/null || echo 0)" > jsmap_status.txt
exit 0`, jsAssetTotalCap), "grep", []string{"httpx_probe"}, 0},
		{"trufflehog_scan", `set +e
: > trufflehog_results.txt
: > trufflehog_stderr.log
printf '{"status":"not_started","inputs":0,"findings":0}\n' > trufflehog_status.json
if ! command -v trufflehog >/dev/null 2>&1; then
  printf '{"status":"not_installed","inputs":0,"findings":0}\n' > trufflehog_status.json
  exit 0
fi
trufflehog --version > trufflehog_version.txt 2> trufflehog_stderr.log || true
INPUTS=()
[ -s clean_katana_urls.txt ] && INPUTS+=(clean_katana_urls.txt)
[ -s js_endpoints.txt ] && INPUTS+=(js_endpoints.txt)
[ -d js_bundles ] && [ -n "$(find js_bundles -type f -size +0c -print -quit 2>/dev/null)" ] && INPUTS+=(js_bundles)
[ -d js_secrets ] && [ -n "$(find js_secrets -type f -size +0c -print -quit 2>/dev/null)" ] && INPUTS+=(js_secrets)
[ -d api_specs ] && [ -n "$(find api_specs -type f -size +0c -print -quit 2>/dev/null)" ] && INPUTS+=(api_specs)
INPUT_COUNT=${#INPUTS[@]}
if [ "$INPUT_COUNT" -eq 0 ]; then
  printf '{"status":"no_inputs","inputs":0,"findings":0}\n' > trufflehog_status.json
  exit 0
fi
trufflehog filesystem "${INPUTS[@]}" --results=verified,unknown --json > trufflehog_results.txt 2> trufflehog_stderr.log
RC=$?
sort -u trufflehog_results.txt -o trufflehog_results.txt 2>/dev/null || true
FINDING_COUNT=$(grep -cve '^$' trufflehog_results.txt 2>/dev/null || echo 0)
if [ "$RC" -eq 0 ]; then STATUS=completed; else STATUS=scan_error; fi
printf '{"status":"%s","inputs":%s,"findings":%s,"exit_code":%s}\n' "$STATUS" "$INPUT_COUNT" "$FINDING_COUNT" "$RC" > trufflehog_status.json
exit 0`, "grep", []string{"clean_urls", "jsmap_scrape", "api_discovery"}, 0},
		{"grep_secrets", `: > potential_secrets.txt
grep -Eih '(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-(test_|live_)?[A-Za-z0-9]{24,}|sk_live_[A-Za-z0-9]{24,}|AIza[0-9A-Za-z_-]{35}|ya29\.[0-9A-Za-z_-]{50,}|eyJ[A-Za-z0-9_=-]+\.eyJ[A-Za-z0-9_=-]+\.[A-Za-z0-9_.+/=-]+|Bearer\s+[A-Za-z0-9._=-]{20,}|["'"'"'\]](api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)["'"'"']?\s*[=:]\s*["'"'"']?[A-Za-z0-9+/=_-]{20,}|[?&](api[_-]?key|apikey|secret|token|access_token|client_secret)=[A-Za-z0-9+/=_-]{20,})' clean_katana_urls.txt 2>/dev/null \
  | grep -Ev '(plaid[_-]?link[_-]?token|_next/static/chunks|pages/lib|/holdings/plaid|/holdings/exchange|ReactPropTypesSecret|auth/refresh[-_]?token|password[-_]?reset|/authentication/v1/|/static/js/.*refresh[-_]?token|exchange[-_]?plaid[-_]?token)' \
  | sort -u > potential_secrets.txt
# Also scan JS bundles for embedded secrets (no URL false positives here)
[ -s js_bundles/ ] && grep -Eroh '(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk-(test_|live_)?[A-Za-z0-9]{24,}|AIza[0-9A-Za-z_-]{35}|eyJ[A-Za-z0-9_=-]+\.eyJ[A-Za-z0-9_=-]+\.[A-Za-z0-9_.+/=-]+|xox[baprs]-[A-Za-z0-9-]{10,}|sk_live_[A-Za-z0-9]{24,}|ya29\.[0-9A-Za-z_-]{50,})' js_bundles/ 2>/dev/null | sort -u >> js_secrets.txt
exit 0`, "grep", []string{"clean_urls", "jsmap_scrape"}, 0},
		{"gau_urls", fmt.Sprintf("[ -s live_subs.txt ] && timeout --foreground %s cat live_subs.txt | gau --threads 5 --subs | tee gau_urls.txt || touch gau_urls.txt", urlMinerTimeout), "default", []string{"merge_brute_subs"}, 10 * time.Minute},
		{"wayback_urls", fmt.Sprintf("[ -s live_subs.txt ] && timeout --foreground %s cat live_subs.txt | waybackurls | tee wayback_urls.txt || touch wayback_urls.txt", urlMinerTimeout), "default", []string{"merge_brute_subs"}, 10 * time.Minute},
		{"merge_all_urls", `: > openapi_paths.txt
for spec in api_specs/*.json; do
  [ -f "$spec" ] || continue
  # Detect host by filename pattern: <host>.<spec>.json
  HOST_FILE=$(basename "$spec" | sed 's/\.[^.]*\.json$//')
  # Restore dots and slashes to recover the host
  HOST=$(echo "$HOST_FILE" | sed 's|_|/|g; s|^|https://|; s|/openapi.json$||; s|/swagger.json$||; s|/_health$||; s|/sitemap.xml$||; s|/robots.txt$||; s|/.well-known/openid-configuration$||')
  # Try jq to extract OpenAPI paths. If the file is not openapi/swagger,
  # jq fails silently and we move on.
  PATHS=$(jq -r '(.paths // {}) | keys[]' "$spec" 2>/dev/null | head -200)
  if [ -n "$PATHS" ]; then
    while read -r P; do
      [ -n "$P" ] && echo "${HOST}${P}" >> openapi_paths.txt
    done <<< "$PATHS"
  fi
  # Also handle sitemap.xml URLs (already full URLs in <loc> tags)
  if echo "$spec" | grep -q "sitemap"; then
    grep -oE '<loc>[^<]+</loc>' "$spec" 2>/dev/null | sed 's|<loc>||;s|</loc>||' >> openapi_paths.txt
  fi
done
sort -u openapi_paths.txt -o openapi_paths.txt 2>/dev/null
touch gau_urls.txt wayback_urls.txt clean_katana_urls.txt
cat gau_urls.txt wayback_urls.txt clean_katana_urls.txt openapi_paths.txt 2>/dev/null | sort -u > all_urls.txt
exit 0`, "default", []string{"gau_urls", "wayback_urls", "clean_urls", "api_discovery"}, 0},
		{"uro_dedup", "if command -v uro >/dev/null 2>&1; then uro < all_urls.txt > uro_urls.txt; cp uro_urls.txt all_urls.txt; else sort -u all_urls.txt -o all_urls.txt; fi", "grep", []string{"merge_all_urls"}, 0},
		{"url_filter_alive", fmt.Sprintf(`%s
if [ -n "$RFUF_EXCLUDE_URL_REGEX" ]; then
  grep -Ev -- "$RFUF_EXCLUDE_URL_REGEX" all_urls.txt > all_urls_scannable.txt || cp all_urls.txt all_urls_scannable.txt
else
  cp all_urls.txt all_urls_scannable.txt
fi
httpx -l all_urls_scannable.txt -silent -status-code -mc 200,301,302,401,403,405 "${AUTH_HEADERS[@]}" -o all_urls_200.txt`, authSnip), "grep", []string{"uro_dedup", "merge_js_endpoints"}, 0},
		{"merge_js_endpoints", `set +e
				cat js_endpoints.txt 2>/dev/null | grep -E '^https?://' | sort -u > js_endpoints_full.txt
				cat all_urls.txt js_endpoints_full.txt 2>/dev/null | grep -E '^https?://' | sort -u > all_urls_with_js.txt
				mv all_urls_with_js.txt all_urls.txt
				printf 'js_endpoints=%s all_urls=%s\\n' "$(wc -l < js_endpoints_full.txt 2>/dev/null || echo 0)" "$(wc -l < all_urls.txt 2>/dev/null || echo 0)" > merge_js_endpoints_status.txt
				exit 0`, "grep", []string{"merge_all_urls", "jsmap_scrape"}, 0},
		{"scope_filter", fmt.Sprintf(`set +e
		filter_stream() {
		  IN="$1"; OUT="$2"; TMP="$OUT.tmp"
		  : > "$TMP"
		  [ -f "$IN" ] || { : > "$OUT"; return 0; }
		  if [ -n "$RFUF_EXCLUDE_URL_REGEX" ]; then
		    grep -Eiv -- "$RFUF_EXCLUDE_URL_REGEX" "$IN" > "$TMP" || :
		  else
		    cp "$IN" "$TMP"
		  fi
		  grep -E '%s' "$TMP" > "$OUT" || :
		  rm -f "$TMP"
		}
		filter_stream all_urls.txt all_urls_scannable.txt
		filter_stream all_urls_200.txt all_urls_200_scannable.txt
		filter_stream js_endpoints.txt js_endpoints_scannable.txt
		head -n "${RFUF_MAX_TARGETS:-10000}" all_urls_scannable.txt > all_urls_scannable.capped 2>/dev/null && mv all_urls_scannable.capped all_urls_scannable.txt || :
		head -n "${RFUF_MAX_TARGETS:-10000}" all_urls_200_scannable.txt > all_urls_200_scannable.capped 2>/dev/null && mv all_urls_200_scannable.capped all_urls_200_scannable.txt || :
		head -n "${RFUF_MAX_TARGETS:-10000}" js_endpoints_scannable.txt > js_endpoints_scannable.capped 2>/dev/null && mv js_endpoints_scannable.capped js_endpoints_scannable.txt || :
		cp all_urls_scannable.txt all_urls.txt 2>/dev/null || :
		cp all_urls_200_scannable.txt all_urls_200.txt 2>/dev/null || :
		cp js_endpoints_scannable.txt js_endpoints.txt 2>/dev/null || :
		printf 'all_urls=%%s all_urls_200=%%s js_endpoints=%%s max_targets=%%s max_stage_requests=%%s\\n' "$(wc -l < all_urls.txt 2>/dev/null || echo 0)" "$(wc -l < all_urls_200.txt 2>/dev/null || echo 0)" "$(wc -l < js_endpoints.txt 2>/dev/null || echo 0)" "${RFUF_MAX_TARGETS:-10000}" "${RFUF_MAX_STAGE_REQUESTS:-300}" > scope_filter_status.txt
		exit 0`, wildcardPattern), "grep", []string{"merge_js_endpoints"}, 0},
		{"nuclei_target_merge", fmt.Sprintf(`set +e
	{
	  awk '{print $1}' alive.txt 2>/dev/null
	  awk '{print $1}' all_urls_200.txt 2>/dev/null
	  cat js_endpoints.txt 2>/dev/null
	} | grep -E '^https?://' | sed 's/[[:space:]]*$//' | sort -u | head -n %d > nuclei_targets.txt
	printf 'inputs alive=%%s urls=%%s js=%%s targets=%%s\\n' "$(wc -l < alive.txt 2>/dev/null || echo 0)" "$(wc -l < all_urls_200.txt 2>/dev/null || echo 0)" "$(wc -l < js_endpoints.txt 2>/dev/null || echo 0)" "$(wc -l < nuclei_targets.txt 2>/dev/null || echo 0)" > nuclei_targets_status.txt
	exit 0`, nucleiTargetCap), "grep", []string{"scope_filter"}, 0},
		{"filter_testable_sqli", fmt.Sprintf(`%s . all_urls_200.txt > sqli_targets_filtered.txt
	[ -s sqli_targets_filtered.txt ] && { gf sqli sqli_targets_filtered.txt >> sqli_targets.txt; grep -Ei '%s' sqli_targets_filtered.txt >> sqli_targets.txt; } || true
	[ -s sqli_targets.txt ] && sort -u sqli_targets.txt -o sqli_targets.txt || touch sqli_targets.txt
	[ -s sqli_targets.txt ] && head -n %d sqli_targets.txt > sqli_targets.txt.capped && mv sqli_targets.txt.capped sqli_targets.txt
	exit 0`, filterTestableRef, sqlmapHighSignalParams, sqlmapTargetCap), "grep", []string{"scope_filter"}, 0},
		{"sqli_targets_replace", `[ -s sqli_targets.txt ] || cp sqli_targets_filtered.txt sqli_targets.txt 2>/dev/null
	exit 0`, "grep", []string{"filter_testable_sqli"}, 0},
		{"sqlmap_scan", fmt.Sprintf(`%s
	%s
	mkdir -p sqlmap_results
	head -n %d sqli_targets.txt > sqlmap_targets.txt 2>/dev/null || : > sqlmap_targets.txt
	TARGET_COUNT=$(wc -l < sqlmap_targets.txt 2>/dev/null || echo 0)
	printf '{"target_count":%%s,"timeout":"%s"}\n' "$TARGET_COUNT" > sqlmap_status.json
	if [ "$TARGET_COUNT" -gt 0 ]; then
	  timeout --foreground %s sqlmap -m sqlmap_targets.txt --batch --random-agent --flush-session --technique=BEUSTQ --level=3 --risk=1 --output-dir=./sqlmap_results "${SQLMAP_AUTH_ARGS[@]}" ${WAF_SQLMAP_TAMPER:+--tamper=$WAF_SQLMAP_TAMPER} > sqlmap_stdout.log 2> sqlmap_stderr.log || true
	fi
	exit 0`, buildAuthSqlmapCmd(), buildWafTamperSnippet(), sqlmapTargetCap, sqlmapScanTimeout, sqlmapScanTimeout), "default", []string{"sqli_targets_replace", "waf_detect"}, 15 * time.Minute},
		{"xss_targets", fmt.Sprintf(`%s . all_urls_200.txt > xss_targets_filtered.txt
	[ -s xss_targets_filtered.txt ] && grep -Ei "q=|search|query|keyword|text|name|email|msg|redirect|url=" xss_targets_filtered.txt > xss_targets.txt
	gf xss xss_targets_filtered.txt >> xss_targets.txt 2>/dev/null || true
	sort -u xss_targets.txt -o xss_targets.txt
	[ -s xss_targets.txt ] && head -n %d xss_targets.txt > xss_targets.txt.capped && mv xss_targets.txt.capped xss_targets.txt
	exit 0`, filterTestableRef, xssScanTargetCap), "grep", []string{"scope_filter"}, 0},
		{"xss_scan", fmt.Sprintf(`%s
	%s
	head -n %d xss_targets.txt > xss_targets_capped.txt
	[ -s xss_targets_capped.txt ] && timeout --foreground %s bash -c 'cat xss_targets_capped.txt | Gxss -p khXSS | dalfox pipe --mining-dom -o xss_vulnerabilities.txt ${WAF_DALFOX_BYPASS:+--bypass=$WAF_DALFOX_BYPASS}'
	touch xss_vulnerabilities.txt
	exit 0`, authSnip, buildWafTamperSnippet(), xssScanTargetCap, xssScanTimeout), "default", []string{"xss_targets", "waf_detect"}, 10 * time.Minute},
		{"rce_targets", fmt.Sprintf(`%s . all_urls_200.txt > rce_targets_filtered.txt
	{ gf rce rce_targets_filtered.txt; grep -Ei '[?&](cmd|exec|command|ping|daemon|upload|shell|code)=' rce_targets_filtered.txt; } | sort -u | head -n %d > rce_targets.txt
	exit 0`, filterTestableRef, maxScanTargets), "grep", []string{"scope_filter"}, 0},
		{"rce_scan", fmt.Sprintf("%s\n[ -s rce_targets.txt ] && nuclei -l rce_targets.txt -tags rce -severity high,critical %s \"${AUTH_HEADERS[@]}\" -o nuclei_rce_rce.txt || : > nuclei_rce_rce.txt", authSnip, nucleiOptimized), "grep", []string{"rce_targets"}, 0},
		{"idor_targets", fmt.Sprintf(`%s . all_urls_200.txt > idor_targets_filtered.txt
	{ gf idor idor_targets_filtered.txt; grep -Ei '[?&](id|account|order|doc|profile|booking|reservation|uid|user_id)=' idor_targets_filtered.txt; } | sort -u | head -n %d > idor_targets.txt
	exit 0`, filterTestableRef, maxScanTargets), "grep", []string{"scope_filter"}, 0},
		{"idor_scan", fmt.Sprintf("%s\nnuclei -l idor_targets.txt -tags idor %s \"${AUTH_HEADERS[@]}\" -o idor_vulnerabilities.txt", authSnip, nucleiOptimized), "grep", []string{"idor_targets"}, 0},
		{"ssrf_targets", fmt.Sprintf(`%s . all_urls_200.txt > ssrf_targets_filtered.txt
	{ gf ssrf ssrf_targets_filtered.txt; grep -Ei "url=|uri=|path=|dest=|redirect=|callback=|webhook=|src=|fetch=|proxy=|target=" ssrf_targets_filtered.txt; } | sort -u > ssrf_targets.txt
	exit 0`, filterTestableRef), "grep", []string{"scope_filter"}, 0},
		{"ssrf_scan", fmt.Sprintf(`%s
	: > ssrf_targets_oob.txt
	: > ssrf_vulnerabilities.txt
	if [ -n "$RFUF_OOB_URL" ]; then
	  sed "s|FOOBAR|$RFUF_OOB_URL|g" ssrf_targets.txt > ssrf_targets_oob.txt
	  nuclei -l ssrf_targets_oob.txt -tags ssrf %s "${AUTH_HEADERS[@]}" -o ssrf_vulnerabilities.txt -var oob_url=$RFUF_OOB_URL
	else
	  nuclei -l ssrf_targets.txt -tags ssrf %s "${AUTH_HEADERS[@]}" -o ssrf_vulnerabilities.txt
	fi
	exit 0`, authSnip, nucleiOptimized, nucleiOptimized), "grep", []string{"ssrf_targets"}, 0},
		{"redirect_targets", fmt.Sprintf(`%s . all_urls_200.txt > redirect_targets_filtered.txt
	gf redirect redirect_targets_filtered.txt | sort -u | head -n %d > redirect_targets.txt
	exit 0`, filterTestableRef, maxScanTargets), "grep", []string{"scope_filter"}, 0},
		{"redirect_scan", fmt.Sprintf("%s\nnuclei -l redirect_targets.txt -tags redirect %s \"${AUTH_HEADERS[@]}\" -o open_redirect_results.txt", authSnip, nucleiOptimized), "grep", []string{"redirect_targets"}, 0},
		{"lfi_targets", fmt.Sprintf(`%s . all_urls_200.txt > lfi_targets_filtered.txt
	gf lfi lfi_targets_filtered.txt > lfi_targets.txt
	sort -u lfi_targets.txt -o lfi_targets.txt
	exit 0`, filterTestableRef), "grep", []string{"scope_filter"}, 0},
		{"lfi_scan", fmt.Sprintf("%s\nnuclei -l lfi_targets.txt -tags lfi %s \"${AUTH_HEADERS[@]}\" -o lfi_results.txt", authSnip, nucleiOptimized), "grep", []string{"lfi_targets"}, 0},
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
		{"dirbrute_ffuf", fmt.Sprintf(`mkdir -p ffuf_results
	if [ -n "%s" ] && [ -s alive.txt ]; then
	  ffuf -w alive.txt:HOST -w %s:WORD -u "HOST/WORD" -mc 200,201,204,301,302,307,308,401,403,405 -ac -t 30 -maxtime 1200 -recursion -recursion-depth 1 -o ffuf_results/all.json -of json -s
	  jq -r '.results[]? | .url' ffuf_results/all.json 2>/dev/null | sort -u > ffuf_dirs_raw.txt
	else
	  : > ffuf_dirs_raw.txt
	fi
	exit 0`, wordlist, wordlist), "default", []string{"httpx_probe"}, 0},
		{"dirbrute_verify_200", "if [ -s ffuf_dirs_raw.txt ]; then httpx -l ffuf_dirs_raw.txt -silent -status-code -mc 200 -o ffuf_dirs_200.txt; else : > ffuf_dirs_200.txt; fi", "grep", []string{"dirbrute_ffuf"}, 0},
		{"js_endpoints_scan", fmt.Sprintf("%s\nnuclei -l js_endpoints.txt -tags exposure,token-spray,misconfig %s \"${AUTH_HEADERS[@]}\" -o js_endpoint_findings.txt", authSnip, nucleiOptimized), "grep", []string{"merge_js_endpoints"}, 0},
		{"nextjs_plaid_jwt_probe", `set +e
	: > nextjs_plaid_jwt_findings.txt

	# Detect Next.js hosts from tech_fingerprint.txt or _next URL prefix
	NEXTJS_HOSTS=$( (grep -E "nextjs," tech_fingerprint.txt 2>/dev/null | awk '{print $1}'; grep -hE "/_next/" all_urls.txt 2>/dev/null | sed 's|/.*||' | sort -u) | sort -u)

	while read HOST; do
	  [ -z "$HOST" ] && continue
	  echo "=== $HOST ===" >> nextjs_//plaid_jwt_findings.txt

	  # 1. Next.js middleware bypass (CVE-2025-29927). The bypass header is
	  #    x-middleware-subrequest with the value 'middleware:middleware:middleware:middleware:middleware'.
	  #    We probe both a likely-auth-protected path and the index.
	  for PATH in /dashboard /api /admin /settings /account /internal /me /api/user; do
	    BASELINE=$(curl -sk --max-time 6 -o /dev/null -w "%{http_code}" "$HOST$PATH" 2>/dev/null)
	    BYPASS=$(curl -sk --max-time 6 -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware" -o /dev/null -w "%{http_code}" "$HOST$PATH" 2>/dev/null)
	    if [ "$BASELINE" != "$BYPASS" ] && [ "$BYPASS" = "200" ] && [ "$BASELINE" != "200" ]; then
	      echo "[CRITICAL] $HOST$PATH — Next.js middleware bypass: baseline=$BASELINE bypass=$BYPASS" >> nextjs_plaid_jwt_findings.txt
	    fi
	  done

		  # 2. Plaid endpoint probe. The Plaid Link flow exposes these paths.
	  for ENDPOINT in /plaid/link/token/create /plaid/exchange_public_token /api/plaid/link/token/create /api/plaid/exchange_public_token /plaid_link_token /api/plaid_link_token /auth/refresh-token /api/auth/refresh-token /auth/refresh_token /api/auth/refresh_token /exchange_plaid_token /api/exchange_plaid_token; do
	    CODE=$(curl -sk --max-time 6 -X POST -H "Content-Type: application/json" -d '{}' -o /dev/null -w "%{http_code}" "$HOST$ENDPOINT" 2>/dev/null)
	    if [ "$CODE" = "200" ]; then
	      echo "[HIGH] $HOST$ENDPOINT — Plaid/auth-token endpoint returns 200 unauthenticated" >> nextjs_plaid_jwt_findings.txt
	    fi
	  done

	  # 3. JWT alg:none. Forge a header.alg=none token with empty signature.
	  JWT_NONE='eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIn0.'
	  for ENDPOINT in /api/me /api/user /api/admin /api/v1/me /api/v2/me /api/v3/me /account /me; do
	    CODE=$(curl -sk --max-time 6 -H "Authorization: Bearer $JWT_NONE" -o /dev/null -w "%{http_code}" "$HOST$ENDPOINT" 2>/dev/null)
	    case "$CODE" in
	      200) echo "[CRITICAL] $HOST$ENDPOINT — JWT alg:none accepted (200)" >> nextjs_plaid_jwt_findings.txt ;;
	    esac
	  done

	  # 4. Next.js source-map leak
	  SAMPLE_JS=$(curl -sk --max-time 6 "$HOST" 2>/dev/null | grep -oE '/_next/static/chunks/[^"]+\.js' | head -1)
	  if [ -n "$SAMPLE_JS" ]; then
	    CODE=$(curl -sk --max-time 6 -o /dev/null -w "%{http_code}" "$HOST${SAMPLE_JS}.map" 2>/dev/null)
	    [ "$CODE" = "200" ] && echo "[MEDIUM] $HOST${SAMPLE_JS}.map — Next.js source map exposed" >> nextjs_plaid_jwt_findings.txt
	  fi
	done <<< "$NEXTJS_HOSTS"
	exit 0`, "grep", []string{"httpx_probe"}, 0},
		{"drf_probe", `set +e
	: > drf_findings.txt
	: > drf_idor_targets.txt

	# Detect DRF hosts: the browsable API footer is near-unique to DRF.
	DRF_HOSTS=$( (grep -E "django|drf|djangorest" tech_fingerprint.txt 2>/dev/null | awk '{print $1}'; curl -sk --max-time 8 "$(head -1 alive.txt 2>/dev/null)/api/v3/" 2>/dev/null | grep -q "Django REST framework" && echo "" ; true) | grep -v '^$' | sort -u )

	# Broaden detection: any alive host whose /api/v3/ (or /api/ /api/v1/ /api/v2/)
	# JSON response carries DRF's signature pagination/links keys, or whose
	# OPTIONS response mentions DRF.
	while read HOST; do
	  [ -z "$HOST" ] && continue
	  echo "$DRF_HOSTS" | grep -qxF "$HOST" && continue
	  for PREFIX in /api/v3/ /api/v2/ /api/v1/ /api/; do
	    # DRF fingerprint: browsable-API footer (HTML) or the DRF pagination +
	    # response-envelope JSON shapes ("next":..., "previous":..., "results":[,
	    # "detail": "Not found.") on a JSON response. A bare "drf" substring is
	    # dropped — it FP'd on unrelated tokens.
	    BODY=$(curl -sk --max-time 8 "$HOST$PREFIX" 2>/dev/null | head -c 30000)
	    if echo "$BODY" | grep -qiE "Django REST framework|rest_framework|\"next\"\s*:\s*\"https?://|\"detail\"\s*:\s*\"Not found|Not found."; then
	      echo "$HOST  django-rest-framework," >> drf_findings.txt
	      continue 2
	    fi
	  done
	done < alive.txt
	sort -u drf_findings.txt -o drf_findings.txt 2>/dev/null

	# Enumerate IDOR-prone detail endpoints under /api/vN/ on DRF hosts.
	# List endpoints discovered in all_urls.txt that look like collection roots
	# (no trailing id) are recorded; the hunter tests ID-swaps manually.
	awk '/\/api\/v[0-9]+\// {print}' all_urls.txt 2>/dev/null \
	  | grep -Ei '/(accounts|users|profiles|orders|invoices|payments|cards|loans|holdings|transactions|events|companies|merchants)/' \
	  | sort -u | head -n 1000 > drf_idor_targets.txt
	exit 0`, "grep", []string{"httpx_probe", "merge_all_urls"}, 0},
		{"bola_surface_run", `set +e
	: > bola_targets.txt
	: > bola_curl.txt
	: > bola_permutations.txt
	# Match UUIDs in URLs like ?company=<uuid> or /<uuid>/. Capture host, path, param, value.
	grep -oE 'https?://[^ ?&]+\?[a-z_]+=[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}' all_urls.txt 2>/dev/null \
	  | while read -r LINE; do
	    URL="${LINE%%\?*}"
	    QS="${LINE#*\?}"
	    PARAM=$(echo "$QS" | cut -d= -f1)
	    UUID=$(echo "$QS" | cut -d= -f2)
	    [ -z "$UUID" ] && continue
	    echo "$URL	$PARAM	$UUID" >> bola_targets.txt
	    # Build ready-to-curl commands: original + 5 adjacent UUIDs (flip last hex digit)
	    ADJ=$(echo "$UUID" | sed 's/.$/1/' ; echo "$UUID" | sed 's/.$/2/' ; echo "$UUID" | sed 's/.$/3/' ; echo "$UUID" | sed 's/.$/a/' ; echo "$UUID" | sed 's/.$/f/')
	    echo "# $URL?$PARAM=$UUID" >> bola_curl.txt
	    while read -r NEW_UUID; do
	      echo "curl -sk --max-time 10 \"$URL?$PARAM=$NEW_UUID\" -o /dev/null -w \"  $NEW_UUID -> %{http_code} %{size_download}B\\n\"" >> bola_curl.txt
	    done <<< "$ADJ"
	    echo "" >> bola_curl.txt
	done
	sort -u bola_targets.txt -o bola_targets.txt 2>/dev/null

	# === Subdomain-aware UUID permutations ===
	# A UUID seen on host-A with param P should also be tested on every OTHER
	# host that accepts the same param P. If the API validates ownership per-
	# company rather than per-session, passing host-B's UUID to host-A's endpoint
	# (or vice versa) is the classic cross-tenant BOLA test. Permutations are
	# bounded: at most 3 foreign UUIDs per (param, host) pair to keep the curl
	# list runnable.
	# Shell implementation: one file per param of all UUIDs seen for it,
	# then emit curl commands for each host+url using up to 3 OTHER UUIDs.
	TMP=$(mktemp -d)
	while IFS="$(printf '\t')" read -r URL PARAM UUID; do
	  echo "$UUID" >> "$TMP/p_$PARAM"
	done < bola_targets.txt
	while IFS="$(printf '\t')" read -r URL PARAM UUID; do
	  OTHERS=$(grep -vxF "$UUID" "$TMP/p_$PARAM" 2>/dev/null | shuf -n 3)
	  [ -z "$OTHERS" ] && continue
	  echo "# cross-tenant: $URL?$PARAM=<foreign-uuid> (original uuid=$UUID)" >> bola_permutations.txt
	  echo "$OTHERS" | while read -r FOREIGN; do
	    echo "curl -sk --max-time 10 \"$URL?$PARAM=$FOREIGN\" -o /dev/null -w \"  foreign=$FOREIGN -> %{http_code} %{size_download}B\\n\"" >> bola_permutations.txt
	  done
	  echo "" >> bola_permutations.txt
	done < bola_targets.txt
	rm -rf "$TMP"
	sort -u bola_permutations.txt -o bola_permutations.txt 2>/dev/null
	exit 0`, "grep", []string{"merge_all_urls"}, 0},
		{"manual_review_queue", `grep -Ei '/(checkout|cart|payment|invoice|order|orders|subscription|seat|fare|booking|reservation|refund|transfer|withdraw|claim|gift|promo|redeem|upgrade|tier|billing|coupon|voucher|wallet|balance|tax|currency)[/?&=_]' all_urls.txt \
	  | grep -Ev '\.(eot|woff2?|ttf|svg|otf|png|jpe?g|gif|ico|css|js|pdf|map|mp[34])([?#]|$)' \
	  | sort -u > manual_business_logic_review.txt
	exit 0`, "grep", []string{"merge_all_urls"}, 0},
		{"waf_detect", "if command -v wafw00f >/dev/null 2>&1; then head -n 200 alive.txt > waf_targets_tmp.txt; wafw00f -i waf_targets_tmp.txt -o waf_detections.txt || true; else : > waf_targets_tmp.txt; : > waf_detections.txt; fi", "grep", []string{"httpx_probe"}, 0},
		{"port_scan_naabu", "if command -v naabu >/dev/null 2>&1; then naabu -list alive.txt -top-ports 1000 -rate 1000 -silent -o naabu_ports.txt || true; else : > naabu_ports.txt; fi", "grep", []string{"httpx_probe"}, 0},
		{"hidden_params_arjun", "if command -v arjun >/dev/null 2>&1 && [ -s alive.txt ]; then head -n 100 alive.txt > arjun_targets_tmp.txt; arjun -i arjun_targets_tmp.txt -oT hidden_params.txt -t 10 --rate-limit 10 || touch hidden_params.txt; rm -f arjun_targets_tmp.txt; else : > hidden_params.txt; fi", "grep", []string{"httpx_probe"}, 0},
		{"ghauri_sqli", "if command -v ghauri >/dev/null 2>&1; then { head -n 200 sqli_targets.txt; grep -Ei '[?&](id|uid|order|product|category|page|article|comment|msg)=' sqli_targets.txt; } | sort -u | head -n 100 > ghauri_targets.txt; [ -s ghauri_targets.txt ] && ghauri -m ghauri_targets.txt --batch --level=2 --risk=1 --technique=BT -o ghauri_results.txt || true; else : > ghauri_results.txt; fi", "grep", []string{"sqli_targets_replace"}, 0},
		{"reflection_run", fmt.Sprintf(`%s reflection . || true
	exit 0`, findingsRunnerRef), "grep", []string{"scope_filter"}, 0},
		{"paramshape_run", fmt.Sprintf(`%s paramshape . || true
	exit 0`, findingsRunnerRef), "grep", []string{"httpx_probe"}, 0},
		{"authshape_run", fmt.Sprintf(`%s authshape . || true
	exit 0`, findingsRunnerRef), "grep", []string{"httpx_probe"}, 0},
		{"signup_takeover_run", fmt.Sprintf(`%s signup . || true
	exit 0`, findingsRunnerRef), "grep", []string{"httpx_probe"}, 0},
		{"idor_surface_run", fmt.Sprintf(`%s idor . || true
	exit 0`, findingsRunnerRef), "grep", []string{"merge_all_urls"}, 0},
		{"oauth_audit_run", fmt.Sprintf(`%s oauth . || true
	exit 0`, findingsRunnerRef), "grep", []string{"httpx_probe"}, 0},
		{"race_scan", fmt.Sprintf(`%s race . || true
	exit 0`, findingsRunnerRef), "grep", []string{"merge_all_urls"}, 0},
		{"bucket_guess_run", fmt.Sprintf(`%s buckets . || true
	exit 0`, findingsRunnerRef), "grep", []string{"tech_fingerprint"}, 0},
		{"takeover_v2_run", fmt.Sprintf(`%s takeoversvc . || true
	exit 0`, findingsRunnerRef), "grep", []string{"httpx_probe"}, 0},
		{"js_mine_run", fmt.Sprintf(`%s jsmine . || true
	exit 0`, findingsRunnerRef), "grep", []string{"jsmap_scrape"}, 0},
		{"secheaders_run", fmt.Sprintf(`%s secheaders . || true
	exit 0`, findingsRunnerRef), "grep", []string{"httpx_probe"}, 0},
		{"backupscan_run", fmt.Sprintf(`%s backupscan . || true
	exit 0`, findingsRunnerRef), "grep", []string{"tech_fingerprint"}, 0},
		{"businesslogic_run", fmt.Sprintf(`%s businesslogic . || true
	exit 0`, findingsRunnerRef), "grep", []string{"merge_all_urls"}, 0},
		{"hostheader_run", fmt.Sprintf(`%s hostheader . || true
	exit 0`, findingsRunnerRef), "grep", []string{"httpx_probe"}, 0},
		{"cors2_run", fmt.Sprintf(`%s cors2 . || true
	exit 0`, findingsRunnerRef), "grep", []string{"httpx_probe"}, 0},
		{"nuclei_rfuf_pass", fmt.Sprintf(`if [ -n "%s" ] && [ -d "%s" ]; then
	  nuclei -l nuclei_targets.txt -t "%s" %s "${AUTH_HEADERS[@]}" -o nuclei_rfuf_pass.txt || true
	else
	  echo "[!] nuclei-templates-rfuf overlay not found — skipping custom template pass"
	  : > nuclei_rfuf_pass.txt
	fi
	exit 0`, paths.NucleiTemplatesRfuf, paths.NucleiTemplatesRfuf, paths.NucleiTemplatesRfuf, nucleiOptimized), "grep", []string{"nuclei_target_merge"}, 0},
	}
}

// buildAuthSqlmapCmd returns a shell preamble that translates RFUF_AUTH_*
// env vars into sqlmap-compatible --cookie / --headers flags. The
// resulting string is intended to be the first line of a multi-line
// `sqlmap_scan` command that uses bash variable expansion to inject auth.
func buildAuthSqlmapCmd() string {
	return `
SQLMAP_AUTH_ARGS=()
[ -n "$RFUF_AUTH_COOKIE" ] && SQLMAP_AUTH_ARGS+=(--cookie "$RFUF_AUTH_COOKIE")
[ -n "$RFUF_AUTH_HEADER" ] && SQLMAP_AUTH_ARGS+=(--headers "Authorization: $RFUF_AUTH_HEADER")
`
}

// nucleiAuthArgs is intentionally no longer a separate helper. Nuclei
// receives the shared "${AUTH_HEADERS[@]}" block from buildAuthHeaderSnippet in each
// stage, so auth behavior cannot silently diverge between scanners.
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

func stageRequired(stepID string) bool {
	// Every declared graph node is required. A scanner may legitimately
	// complete with zero findings, but a skipped, timed-out, failed, or
	// blocked node must make the final coverage report incomplete.
	return true
}

func ensureZeroResultArtifacts(workDir, stepID string, outputs []string) error {
	if !softStages[stepID] {
		return nil
	}
	for _, path := range outputs {
		clean := filepath.Clean(path)
		if filepath.IsAbs(clean) || clean == "." || strings.HasPrefix(clean, "..") {
			continue
		}
		full := filepath.Join(workDir, clean)
		if _, err := os.Stat(full); err == nil {
			continue
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("cannot inspect zero-result artifact %s: %w", clean, err)
		}
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			return fmt.Errorf("cannot create artifact directory for %s: %w", clean, err)
		}
		file, err := os.OpenFile(full, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("cannot create zero-result artifact %s: %w", clean, err)
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("cannot close zero-result artifact %s: %w", clean, err)
		}
	}
	return nil
}

func stageArtifacts(step Step) (inputs, outputs []string) {
	inputs = coverage.ExtractInputPaths(step.Command)
	outputs = coverage.ExtractOutputPaths(step.Command)
	knownInputs := map[string][]string{
		"scope_guard":          {"subs.txt"},
		"jsmap_scrape":         {"alive.txt"},
		"merge_all_urls":       {"gau_urls.txt", "wayback_urls.txt", "clean_katana_urls.txt", "openapi_paths.txt"},
		"url_filter_alive":     {"all_urls_scannable.txt"},
		"merge_js_endpoints":   {"all_urls.txt", "js_endpoints.txt"},
		"scope_filter":         {"all_urls.txt", "all_urls_200.txt", "js_endpoints.txt"},
		"nuclei_target_merge":  {"alive.txt", "all_urls_200.txt", "js_endpoints.txt"},
		"filter_testable_sqli": {"all_urls_200.txt"},
		"xss_targets":          {"all_urls_200.txt"},
		"rce_targets":          {"all_urls_200.txt"},
		"idor_targets":         {"all_urls_200.txt"},
		"ssrf_targets":         {"all_urls_200.txt"},
		"redirect_targets":     {"all_urls_200.txt"},
		"lfi_targets":          {"all_urls_200.txt"},
	}
	known := map[string][]string{
		"scope_guard":         {"scope.json", "in_scope_hosts.txt", "out_of_scope_hosts.txt", "scoped_subs.txt"},
		"subfinder":           {"subfinder.txt"},
		"assetfinder":         {"assetfinder.txt"},
		"amass_enum":          {"amass_raw.txt"},
		"dnsx_resolve":        {"live_subs.txt"},
		"httpx_probe":         {"alive.txt"},
		"jsmap_scrape":        {"js_assets.txt", "js_endpoints.txt", "jsmap_status.txt"},
		"merge_all_urls":      {"all_urls.txt"},
		"url_filter_alive":    {"all_urls_200.txt"},
		"merge_js_endpoints":  {"all_urls.txt", "js_endpoints_full.txt"},
		"scope_filter":        {"all_urls.txt", "all_urls_200.txt", "js_endpoints.txt", "scope_filter_status.txt"},
		"nuclei_target_merge": {"nuclei_targets.txt"},
		"sqlmap_scan":         {"sqlmap_targets.txt", "sqlmap_status.json"},
		"trufflehog_scan":     {"trufflehog_status.json", "trufflehog_results.txt"},
		"nuclei_exposures":    {"credentials_found.txt"},
		"nuclei_misconfigs":   {"misconfigs.txt"},
		"nuclei_auth_scan":    {"auth_results.txt"},
		"nuclei_graphql_scan": {"graphql_exposed.txt"},
		"cors_check":          {"cors_findings.txt"},
		"dirbrute_verify_200": {"ffuf_dirs_200.txt"},
		"js_endpoints_scan":   {"js_endpoint_findings.txt"},
		"ghauri_sqli":         {"ghauri_results.txt"},
		"hidden_params_arjun": {"hidden_params.txt"},
	}
	inputs = append(inputs, knownInputs[step.ID]...)
	outputs = append(outputs, known[step.ID]...)
	return uniquePaths(inputs), uniquePaths(outputs)
}

func uniquePaths(paths []string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		out = append(out, path)
	}
	return out
}

func writeBlockedRecords(workDir string, steps []Step) error {
	records, err := coverage.LoadStageRecords(workDir)
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(records))
	for _, record := range records {
		seen[record.StageID] = true
	}
	for _, step := range steps {
		if seen[step.ID] {
			continue
		}
		now := time.Now()
		if err := coverage.WriteStageRecord(workDir, coverage.StageRecord{StageID: step.ID, Required: stageRequired(step.ID), Dependencies: step.Deps, Status: coverage.StatusBlocked, StartedAt: now, FinishedAt: now, SkipReason: "not_started_due_to_previous_stage_failure"}); err != nil {
			return err
		}
	}
	return nil
}

func finalizeRun(domain string, paths *config.Paths, cp *checkpoint.Checkpoint, steps []Step, startedAt time.Time, runErr error) error {
	if err := writeBlockedRecords(paths.WorkDir, steps); err != nil && runErr == nil {
		runErr = err
	}
	stageRecords, err := coverage.LoadStageRecords(paths.WorkDir)
	var report coverage.CoverageReport
	if err != nil && runErr == nil {
		runErr = err
	}
	if err == nil {
		report = coverage.Evaluate(domain, startedAt, time.Now(), stageRecords)
		if writeErr := coverage.WriteReport(paths.WorkDir, report); writeErr != nil && runErr == nil {
			runErr = writeErr
		}
		if report.Status != "COMPLETE" && runErr == nil {
			runErr = fmt.Errorf("coverage incomplete: %s", strings.Join(report.RequiredIssues, "; "))
		}
	}
	evidenceRecords, evidenceErr := evidence.BuildIndex(paths.WorkDir)
	if evidenceErr != nil && runErr == nil {
		runErr = evidenceErr
	} else if evidenceErr == nil {
		if writeErr := evidence.WriteIndex(paths.WorkDir, evidenceRecords); writeErr != nil && runErr == nil {
			runErr = writeErr
		}
		if err == nil {
			if writeErr := owasp.Generate(paths.WorkDir, domain, report, stageRecords, evidenceRecords); writeErr != nil && runErr == nil {
				runErr = writeErr
			}
		}
	}
	if summaryErr := summary.Generate(paths.WorkDir, cp); summaryErr != nil && runErr == nil {
		runErr = summaryErr
	}
	return runErr
}

func Run(domain string, resume bool, paths *config.Paths, stepTimeout time.Duration) error {
	parsed, err := scope.Parse(domain)
	if err != nil {
		return err
	}
	return RunForScope(parsed, resume, paths, stepTimeout)
}

func validateResumeScope(workDir string, expected scope.Scope) error {
	data, err := os.ReadFile(filepath.Join(workDir, "scope.json"))
	if err != nil {
		return fmt.Errorf("cannot resume: scope metadata is missing; rerun without -resume to establish %s mode", expected.Mode)
	}
	var recorded struct {
		Input      string     `json:"input"`
		RootDomain string     `json:"root_domain"`
		Mode       scope.Mode `json:"mode"`
	}
	if err := json.Unmarshal(data, &recorded); err != nil {
		return fmt.Errorf("cannot resume: invalid scope.json: %w", err)
	}
	if recorded.RootDomain != expected.RootDomain || recorded.Mode != expected.Mode {
		return fmt.Errorf("cannot resume: existing scan is %s mode for %s, but this command requested %s mode for %s; rerun without -resume for a new scope", recorded.Mode, recorded.RootDomain, expected.Mode, expected.RootDomain)
	}
	return nil
}

func RunForScope(scanScope scope.Scope, resume bool, paths *config.Paths, stepTimeout time.Duration) error {
	domain := scanScope.RootDomain
	cp, err := checkpoint.Load(paths.WorkDir, domain)
	if err != nil {
		return err
	}
	if resume {
		if err := validateResumeScope(paths.WorkDir, scanScope); err != nil {
			return err
		}
	}

	// Capture the dashboard start time AFTER any checkpoint reset so a
	// fresh re-run against an existing work dir shows wall-clock elapsed
	// from this invocation, not from the previous one. On -resume we
	// intentionally keep cp.StartedAt so elapsed reflects total work.
	startTime := cp.StartedAt
	if !resume {
		if len(cp.CompletedSteps) > 0 {
			if err := cp.Reset(); err != nil {
				return fmt.Errorf("failed to reset checkpoint: %w", err)
			}
		}
		if err := os.RemoveAll(filepath.Join(paths.WorkDir, ".rfuf", "stages")); err != nil {
			return fmt.Errorf("failed to reset stage records: %w", err)
		}
		startTime = cp.StartedAt
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

	steps := GetStepsForScope(scanScope, paths)
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

	records, _ := coverage.LoadStageRecords(paths.WorkDir)
	for _, s := range steps {
		if cp.IsCompleted(s.ID) {
			if softStages[s.ID] {
				isBad := false
				for _, r := range records {
					if r.StageID == s.ID && (r.Status == coverage.StatusTimedOut || r.Status == coverage.StatusFailed) {
						isBad = true
						break
					}
				}
				if isBad {
					continue // Force re-run
				}
			}
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
	stopAndWait := func(runErr error) error {
		cancel()
		wg.Wait()
		cli.StopDashboard()
		executor.LineCallback = nil
		return finalizeRun(domain, paths, cp, steps, startTime, runErr)
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
					now := time.Now()
					_ = coverage.WriteStageRecord(paths.WorkDir, coverage.StageRecord{StageID: s.ID, Required: stageRequired(s.ID), Dependencies: s.Deps, Status: coverage.StatusSkipped, StartedAt: now, FinishedAt: now, SkipReason: "wordlist_missing"})
					completed[s.ID] = true
					cp.CompleteStep(s.ID)
					continue
				}

				running[s.ID] = true
				startedAny = true
				wg.Add(1)
				go func(step Step) {
					defer wg.Done()
					inputs, outputs := stageArtifacts(step)
					started := time.Now()
					_ = coverage.WriteStageRecord(paths.WorkDir, coverage.StageRecord{StageID: step.ID, Required: stageRequired(step.ID), Dependencies: step.Deps, Status: coverage.StatusRunning, StartedAt: started, InputArtifacts: coverage.MeasureArtifacts(paths.WorkDir, inputs), OutputArtifacts: coverage.MeasureArtifacts(paths.WorkDir, outputs)})
					select {

					case semaphore <- struct{}{}:
					case <-ctx.Done():
						now := time.Now()
						_ = coverage.WriteStageRecord(paths.WorkDir, coverage.StageRecord{StageID: step.ID, Required: stageRequired(step.ID), Dependencies: step.Deps, Status: coverage.StatusBlocked, StartedAt: started, FinishedAt: now, SkipReason: "cancelled_before_start"})
						return
					}
					defer func() { <-semaphore }()

					res, err := executor.RunCommand(ctx, step.Command, paths.WorkDir, logFile, effectiveStepTimeout(stepTimeout, step.Timeout))
					if err == nil && res.ExitCode == 0 {
						_, outputs := stageArtifacts(step)
						if materializeErr := ensureZeroResultArtifacts(paths.WorkDir, step.ID, outputs); materializeErr != nil {
							err = materializeErr
						}
					}

					mu.Lock()
					delete(running, step.ID)
					inputMetrics := coverage.MeasureArtifacts(paths.WorkDir, inputs)
					outputMetrics := coverage.MeasureArtifacts(paths.WorkDir, outputs)
					if err != nil {
						now := time.Now()
						_ = coverage.WriteStageRecord(paths.WorkDir, coverage.StageRecord{StageID: step.ID, Required: stageRequired(step.ID), Dependencies: step.Deps, Status: coverage.StatusFailed, StartedAt: started, FinishedAt: now, ExitCode: -1, Error: err.Error(), InputArtifacts: inputMetrics, OutputArtifacts: outputMetrics, InputCount: coverage.CountMetrics(inputMetrics), OutputCount: coverage.CountMetrics(outputMetrics)})
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
					status := coverage.StatusCompleted
					missingOutput := false
					for _, metric := range outputMetrics {
						if !metric.Exists {
							missingOutput = true
							break
						}
					}
					// A clean tool exit with no output is NOT a failure. It
					// usually means the input was empty (e.g. SQLi targets
					// got filtered to zero URLs on this domain), so the
					// scanner had nothing to test and wrote no findings.
					// Treat that as completed_empty and continue, not as a
					// pipeline-fatal failure.
					emptyInput := coverage.CountMetrics(inputMetrics) == 0
					if res.TimedOut {
														if softStages[step.ID] {
									_, outputs := stageArtifacts(step)
									_ = ensureZeroResultArtifacts(paths.WorkDir, step.ID, outputs)
									outputMetrics = coverage.MeasureArtifacts(paths.WorkDir, outputs)
									status = coverage.StatusCompletedEmpty

								// If it's a soft stage that timed out, we treat it as completed_empty
								// so the pipeline can proceed.
								_ = coverage.WriteStageRecord(paths.WorkDir, coverage.StageRecord{StageID: step.ID, Required: stageRequired(step.ID), Dependencies: step.Deps, Status: status, StartedAt: started, FinishedAt: time.Now(), ExitCode: res.ExitCode, InputArtifacts: inputMetrics, OutputArtifacts: outputMetrics, InputCount: coverage.CountMetrics(inputMetrics), OutputCount: coverage.CountMetrics(outputMetrics)})
								completed[step.ID] = true
								cp.CompleteStep(step.ID)
								mu.Unlock()
								return
								} else {
									status = coverage.StatusTimedOut
								}

					} else if missingOutput && (emptyInput || res.ExitCode == 0) {
						status = coverage.StatusCompletedEmpty
					} else if missingOutput {
						status = coverage.StatusFailed
					} else if coverage.CountMetrics(outputMetrics) == 0 {
						status = coverage.StatusCompletedEmpty
					}

					// A status of completed_empty (clean exit, no output)
					// is never a pipeline failure — the tool did its job,
					// there was just nothing to do. Skip the errChan and
					// fall through to the success path that marks the
					// step complete.
					if status == coverage.StatusCompletedEmpty {
						_ = coverage.WriteStageRecord(paths.WorkDir, coverage.StageRecord{StageID: step.ID, Required: stageRequired(step.ID), Dependencies: step.Deps, Status: status, StartedAt: started, FinishedAt: time.Now(), ExitCode: res.ExitCode, InputArtifacts: inputMetrics, OutputArtifacts: outputMetrics, InputCount: coverage.CountMetrics(inputMetrics), OutputCount: coverage.CountMetrics(outputMetrics)})
						completed[step.ID] = true
						cp.CompleteStep(step.ID)
						mu.Unlock()
						return
					}

					if !success || res.TimedOut || missingOutput {
						if !res.TimedOut {
							status = coverage.StatusFailed
						}

						now := time.Now()
						_ = coverage.WriteStageRecord(paths.WorkDir, coverage.StageRecord{StageID: step.ID, Required: stageRequired(step.ID), Dependencies: step.Deps, Status: status, StartedAt: started, FinishedAt: now, ExitCode: res.ExitCode, TimedOut: res.TimedOut, Error: fmt.Sprintf("exit_code=%d", res.ExitCode), InputArtifacts: inputMetrics, OutputArtifacts: outputMetrics, InputCount: coverage.CountMetrics(inputMetrics), OutputCount: coverage.CountMetrics(outputMetrics)})
						mu.Unlock()
						errChan <- fmt.Errorf("step %s incomplete (status=%s exit_code=%d)", step.ID, status, res.ExitCode)
						return
					}

					_ = coverage.WriteStageRecord(paths.WorkDir, coverage.StageRecord{StageID: step.ID, Required: stageRequired(step.ID), Dependencies: step.Deps, Status: status, StartedAt: started, FinishedAt: time.Now(), ExitCode: res.ExitCode, InputArtifacts: inputMetrics, OutputArtifacts: outputMetrics, InputCount: coverage.CountMetrics(inputMetrics), OutputCount: coverage.CountMetrics(outputMetrics)})
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

	// Leave alt-screen BEFORE the final summary banner so the user sees
	// their real shell prompt on success or incomplete coverage.
	cli.StopDashboard()
	executor.LineCallback = nil
	if err := finalizeRun(domain, paths, cp, steps, startTime, nil); err != nil {
		fmt.Printf("\n[!] Pipeline incomplete: %v\nOutput saved to %s\n", err, paths.WorkDir)
		return err
	}

	fmt.Printf("\n[+] Pipeline complete! Output saved to %s\n", paths.WorkDir)
	return nil
}
