package pipeline

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CyberShuriken/rfuf/internal/checkpoint"
	"github.com/CyberShuriken/rfuf/internal/config"
	"github.com/CyberShuriken/rfuf/internal/coverage"
)

func TestXSSScanUsesSupportedDalfoxFlags(t *testing.T) {
	steps := GetSteps("example.com", &config.Paths{})

	for _, step := range steps {
		if step.ID != "xss_scan" {
			continue
		}

		if strings.Contains(step.Command, "--batch") {
			t.Fatalf("xss_scan uses obsolete Dalfox flag: %q", step.Command)
		}
		// The new pipeline uses --mining-dom (a 2024-era dalfox flag that
		// catches DOM-based XSS hiding in JS-loaded parameters). We also
		// accept any dalfox pipe invocation into xss_vulnerabilities.txt.
		if !strings.Contains(step.Command, "dalfox pipe") {
			t.Fatalf("xss_scan must invoke dalfox pipe: %q", step.Command)
		}
		if !strings.Contains(step.Command, "xss_vulnerabilities.txt") {
			t.Fatalf("xss_scan must write to xss_vulnerabilities.txt: %q", step.Command)
		}
		return
	}

	t.Fatal("xss_scan step not found")
}

// TestAmassFailureDoesNotAbortPipeline covers Kali's packaged Amass builds,
// which can exit 1 when a passive data source is unavailable. Enumeration
// still has subfinder and assetfinder, so the Amass stage must preserve any
// partial output and report success to the scheduler.
func TestAmassFailureDoesNotAbortPipeline(t *testing.T) {
	steps := GetSteps("example.com", &config.Paths{})
	for _, step := range steps {
		if step.ID != "amass_enum" {
			continue
		}
		if !strings.Contains(step.Command, "if ! amass enum") {
			t.Fatalf("amass_enum must handle a non-zero Amass exit: %q", step.Command)
		}
		if !strings.Contains(step.Command, "touch amass_raw.txt") {
			t.Fatalf("amass_enum must provide an empty-file fallback: %q", step.Command)
		}
		return
	}
	t.Fatal("amass_enum step not found")
}

func TestReconArtifactContractsMatchProducerFiles(t *testing.T) {
	steps := GetSteps("example.com", &config.Paths{})
	for _, want := range []struct {
		id     string
		output string
	}{
		{id: "subfinder", output: "subfinder.txt"},
		{id: "amass_enum", output: "amass_raw.txt"},
	} {
		var step Step
		found := false
		for _, candidate := range steps {
			if candidate.ID == want.id {
				step = candidate
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("%s step not found", want.id)
		}
		_, outputs := stageArtifacts(step)
		if !containsString(outputs, want.output) {
			t.Fatalf("%s must validate %s, got %v", want.id, want.output, outputs)
		}
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// TestDirbruteUsesRecursion guards against the slow per-host loop
// regressing back in. The fast path is one ffuf invocation with two
// wordlists (-w hosts.txt:HOST + -w words.txt:WORD), recursion enabled
// at depth 1 (depth 2 was the hang-on-localwp.com regression), and a
// 20-minute cap. Per-host bash loops are forbidden.
func TestDirbruteUsesRecursion(t *testing.T) {
	steps := GetSteps("example.com", &config.Paths{SeclistsDirWordlistSmall: "/tmp/small.txt"})

	var cmd string
	for _, s := range steps {
		if s.ID == "dirbrute_ffuf" {
			cmd = s.Command
			break
		}
	}
	if cmd == "" {
		t.Fatal("dirbrute_ffuf step not found")
	}
	if !strings.Contains(cmd, "-recursion") {
		t.Errorf("dirbrute_ffuf missing -recursion (slow path regression): %q", cmd)
	}
	if !strings.Contains(cmd, "-recursion-depth 1") {
		t.Errorf("dirbrute_ffuf must use -recursion-depth 1 (depth 2 hangs): %q", cmd)
	}
	if !strings.Contains(cmd, "-maxtime 1200") {
		t.Errorf("dirbrute_ffuf must set -maxtime 1200 (20-min ceiling): %q", cmd)
	}
	if !strings.Contains(cmd, "alive.txt:HOST") {
		t.Errorf("dirbrute_ffuf should use two-wordlist mode (-w alive.txt:HOST): %q", cmd)
	}
	if strings.Contains(cmd, "while read") {
		t.Errorf("dirbrute_ffuf regressed to per-host bash loop: %q", cmd)
	}
}

// TestUrlFilterAliveExists ensures the URL-alive filter step is wired
// into the pipeline. Without it, downstream vuln scanners (sqlmap,
// dalfox, nuclei) waste time on dead URLs from gau/wayback.
//
// Note: the new policy accepts 200, 301, 302, 401, 403, 405 — not just
// 200. The previous -mc 200 only filter dropped 8655 of 8740 URLs on
// localwp.com because Cloudflare's bot detection returned 403 on
// otherwise-real endpoints. 401/403/405 are testable endpoints requiring
// auth (or POST on a GET-only endpoint); 301/302 may redirect to a
// testable path.
func TestUrlFilterAliveExists(t *testing.T) {
	steps := GetSteps("example.com", &config.Paths{})
	var cmd, id string
	for _, s := range steps {
		if s.ID == "url_filter_alive" {
			id = s.ID
			cmd = s.Command
			break
		}
	}
	if id == "" {
		t.Fatal("url_filter_alive step missing — vuln scans will waste time on 404 URLs")
	}
	if !strings.Contains(cmd, "-mc 200") {
		t.Errorf("url_filter_alive must include -mc 200 (and auth-skipping codes): %q", cmd)
	}
	if !strings.Contains(cmd, "-mc 200,301,302,401,403,405") {
		t.Errorf("url_filter_alive must accept 200,301,302,401,403,405 (Cloudflare fronted endpoints 403 legitimately): %q", cmd)
	}
	if !strings.Contains(cmd, "all_urls_200.txt") {
		t.Errorf("url_filter_alive must write to all_urls_200.txt: %q", cmd)
	}
}

// TestDirbruteVerifyExists guards the second-stage prune step. Without
// it, ffuf_dirs_200.txt would still contain 301/302/403 entries — and
// the user's "only test 200" rule would be violated downstream.
func TestDirbruteVerifyExists(t *testing.T) {
	steps := GetSteps("example.com", &config.Paths{})
	var id, deps, cmd string
	for _, s := range steps {
		if s.ID == "dirbrute_verify_200" {
			id = s.ID
			cmd = s.Command
			deps = s.Deps[0]
			break
		}
	}
	if id == "" {
		t.Fatal("dirbrute_verify_200 step missing — 200-only verification broken")
	}
	if deps != "dirbrute_ffuf" {
		t.Errorf("dirbrute_verify_200 must depend on dirbrute_ffuf, got %q", deps)
	}
	if !strings.Contains(cmd, "ffuf_dirs_200.txt") {
		t.Errorf("dirbrute_verify_200 must write ffuf_dirs_200.txt: %q", cmd)
	}
}

// TestSqlmapScanHardened checks that sqlmap is run with the
// false-positive-resistant flag set. The legacy --level=2 --risk=2
// combo produces the noise that originally motivated this refactor.
func TestSqlmapScanHardened(t *testing.T) {
	steps := GetSteps("example.com", &config.Paths{})
	for _, s := range steps {
		if s.ID != "sqlmap_scan" {
			continue
		}
		if !strings.Contains(s.Command, "--level=3") {
			t.Errorf("sqlmap_scan must use --level=3 for header/cookie coverage: %q", s.Command)
		}
		if !strings.Contains(s.Command, "--risk=1") {
			t.Errorf("sqlmap_scan must use --risk=1 to skip error/stacked noise: %q", s.Command)
		}
		if !strings.Contains(s.Command, "--technique=BEUSTQ") {
			t.Errorf("sqlmap_scan must pin --technique=BEUSTQ: %q", s.Command)
		}
		if strings.Contains(s.Command, "--risk=2") {
			t.Errorf("sqlmap_scan regressed to --risk=2 (highest-noise combo): %q", s.Command)
		}
		return
	}
	t.Fatal("sqlmap_scan step not found")
}

// TestVulnTargetsSourceFrom200Only ensures every *_targets step sources
// from all_urls_200.txt (the 200-only filtered stream) rather than
// all_urls.txt (which contains dead historical URLs).
//
// Step-name migration: the SQLi stage was previously a single step
// (sqli_targets). It is now filter_testable_sqli — a two-stage pipeline
// that runs the new filter_testable helper first, then applies gf sqli
// + the legacy high-signal-param regex. The fallback step
// (sqli_targets_replace) only activates when filter_testable_sqli
// produced empty output, so it knowingly sources from the filtered
// intermediate file rather than all_urls_200.txt.
func TestVulnTargetsSourceFrom200Only(t *testing.T) {
	steps := GetSteps("example.com", &config.Paths{})
	scanSteps := []string{
		"filter_testable_sqli", "xss_targets", "rce_targets",
		"idor_targets", "ssrf_targets", "redirect_targets", "lfi_targets",
	}
	for _, want := range scanSteps {
		found := false
		for _, s := range steps {
			if s.ID != want {
				continue
			}
			found = true
			if !strings.Contains(s.Command, "all_urls_200.txt") {
				t.Errorf("%s must source from all_urls_200.txt, got: %q", want, s.Command)
			}
			depOK := false
			for _, d := range s.Deps {
				if d == "scope_filter" {

					depOK = true
					break
				}
			}
			if !depOK {
				t.Errorf("%s must depend on scope_filter, deps=%v", want, s.Deps)

			}
			break
		}
		if !found {
			t.Errorf("%s step missing", want)
		}
	}
}

func TestSqlmapUsesMaterializedTargetFile(t *testing.T) {
	steps := GetSteps("example.com", &config.Paths{})
	for _, s := range steps {
		if s.ID != "sqlmap_scan" {
			continue
		}
		if !strings.Contains(s.Command, "sqlmap_targets.txt") {
			t.Fatalf("sqlmap_scan must use a materialized target file: %q", s.Command)
		}
		if strings.Contains(s.Command, "<(head") {
			t.Fatalf("sqlmap_scan regressed to process substitution: %q", s.Command)
		}
		if !strings.Contains(s.Command, "sqlmap_status.json") {
			t.Fatalf("sqlmap_scan must emit status diagnostics: %q", s.Command)
		}
		return
	}
	t.Fatal("sqlmap_scan step not found")
}

func TestNucleiHostScansUseEnrichedTargets(t *testing.T) {
	steps := GetSteps("example.com", &config.Paths{})
	want := map[string]bool{
		"nuclei_exposures":    false,
		"nuclei_misconfigs":   false,
		"nuclei_auth_scan":    false,
		"nuclei_graphql_scan": false,
	}
	for _, s := range steps {
		if _, ok := want[s.ID]; !ok {
			continue
		}
		want[s.ID] = true
		if !strings.Contains(s.Command, "nuclei_targets.txt") {
			t.Errorf("%s must scan nuclei_targets.txt: %q", s.ID, s.Command)
		}
		depOK := false
		for _, d := range s.Deps {
			if d == "nuclei_target_merge" {
				depOK = true
			}
		}
		if !depOK {
			t.Errorf("%s must depend on nuclei_target_merge: %v", s.ID, s.Deps)
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("%s step missing", id)
		}
	}
}

func TestJavaScriptCollectionCoversModernAssets(t *testing.T) {
	steps := GetSteps("example.com", &config.Paths{})
	for _, s := range steps {
		if s.ID != "jsmap_scrape" {
			continue
		}
		for _, marker := range []string{"manifest.json", "asset-manifest.json", "/_next/static/", "/static/js/", "RFUF_AUTH_COOKIE", "js_assets.txt"} {
			if !strings.Contains(s.Command, marker) {
				t.Errorf("jsmap_scrape missing %q: %q", marker, s.Command)
			}
		}
		return
	}
	t.Fatal("jsmap_scrape step not found")
}

func TestTrufflehogRecordsStatusAndDiagnostics(t *testing.T) {
	steps := GetSteps("example.com", &config.Paths{})
	for _, s := range steps {
		if s.ID != "trufflehog_scan" {
			continue
		}
		for _, marker := range []string{"trufflehog_status.json", "trufflehog_stderr.log", "--json", "no_inputs", "not_installed", "scan_error"} {
			if !strings.Contains(s.Command, marker) {
				t.Errorf("trufflehog_scan missing %q: %q", marker, s.Command)
			}
		}
		return
	}
	t.Fatal("trufflehog_scan step not found")
}

func TestProgramHeadersReachShellStages(t *testing.T) {
	steps := GetSteps("example.com", &config.Paths{})
	for _, s := range steps {
		if s.ID != "httpx_probe" && s.ID != "nuclei_exposures" && s.ID != "jsmap_scrape" {
			continue
		}
		if !strings.Contains(s.Command, "X-Bug-Bounty") {
			t.Errorf("%s must propagate X-Bug-Bounty: %q", s.ID, s.Command)
		}
		if !strings.Contains(s.Command, "X-Test-Account-Email") {
			t.Errorf("%s must propagate X-Test-Account-Email: %q", s.ID, s.Command)
		}
	}
}

func TestURLFilterSupportsProgramExclusions(t *testing.T) {
	steps := GetSteps("example.com", &config.Paths{})
	for _, s := range steps {
		if s.ID != "url_filter_alive" {
			continue
		}
		for _, marker := range []string{"RFUF_EXCLUDE_URL_REGEX", "all_urls_scannable.txt", "grep -Ev"} {
			if !strings.Contains(s.Command, marker) {
				t.Errorf("url_filter_alive missing %q: %q", marker, s.Command)
			}
		}
		return
	}
	t.Fatal("url_filter_alive step not found")
}

func TestScopeFilterIsFinalBoundary(t *testing.T) {
	steps := GetSteps("example.com", &config.Paths{})
	var scopeIndex, mergeIndex, targetIndex int
	for i, step := range steps {
		switch step.ID {
		case "merge_js_endpoints":
			mergeIndex = i
		case "scope_filter":
			scopeIndex = i
			for _, marker := range []string{"RFUF_EXCLUDE_URL_REGEX", "RFUF_MAX_TARGETS", "all_urls_200.txt", "js_endpoints.txt"} {
				if !strings.Contains(step.Command, marker) {
					t.Errorf("scope_filter missing %q", marker)
				}
			}
		case "nuclei_target_merge":
			targetIndex = i
		}
	}
	if scopeIndex <= mergeIndex || targetIndex <= scopeIndex {
		t.Fatalf("expected merge < scope_filter < nuclei target merge, got merge=%d scope=%d target=%d", mergeIndex, scopeIndex, targetIndex)
	}
}

func TestScopeFilterFixtureRemovesExcludedAndOutOfDomainURLs(t *testing.T) {
	var command string
	for _, step := range GetSteps("example.com", &config.Paths{}) {
		if step.ID == "scope_filter" {
			command = step.Command
			break
		}
	}
	if command == "" {
		t.Fatal("scope_filter step not found")
	}
	dir := t.TempDir()
	for name, body := range map[string]string{
		"all_urls.txt":     "https://app.example.com/api\nhttps://app.example.com/contact/sales\nhttps://evil.example.net/out\n",
		"all_urls_200.txt": "https://app.example.com/api [200]\nhttps://app.example.com/contact/sales [200]\n",
		"js_endpoints.txt": "https://app.example.com/api/v1\nhttps://app.example.com/support/ticket\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("bash", "-c", command)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "RFUF_EXCLUDE_URL_REGEX=(^|/)(contact|support)(/|$)", "RFUF_MAX_TARGETS=100")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("scope_filter failed: %v output=%s", err, output)
	}
	data, err := os.ReadFile(filepath.Join(dir, "all_urls.txt"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "contact") || strings.Contains(text, "evil.example.net") || !strings.Contains(text, "api") {
		t.Fatalf("scope filter output=%q", text)
	}
}

func TestFinalizeRunWritesIncompleteCoverageArtifacts(t *testing.T) {
	dir := t.TempDir()
	cp, err := checkpoint.Load(dir, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	steps := []Step{{ID: "required_stage", Deps: nil}}
	if err := coverage.WriteStageRecord(dir, coverage.StageRecord{StageID: "required_stage", Required: true, Status: coverage.StatusFailed, ExitCode: 1}); err != nil {
		t.Fatal(err)
	}
	paths := &config.Paths{WorkDir: dir}
	if err := finalizeRun("example.com", paths, cp, steps, time.Now(), errors.New("stage failed")); err == nil {
		t.Fatal("expected finalization to retain the stage error")
	}
	data, err := os.ReadFile(filepath.Join(dir, ".rfuf", "coverage_report.json"))
	if err != nil || !strings.Contains(string(data), "INCOMPLETE") {
		t.Fatalf("coverage report missing or not incomplete: err=%v data=%s", err, data)
	}
	for _, name := range []string{"CoverageReport.md", "SUMMARY.md", "findings.md", "evidence.jsonl"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("missing final artifact %s: %v", name, err)
		}
	}
}

func TestNucleiUsesConfiguredRateLimit(t *testing.T) {
	steps := GetSteps("example.com", &config.Paths{})
	for _, step := range steps {
		if strings.Contains(step.Command, "nuclei ") && !strings.Contains(step.Command, "RFUF_MAX_STAGE_REQUESTS") {
			t.Errorf("nuclei step %s does not use configured request ceiling", step.ID)
		}
	}
}
