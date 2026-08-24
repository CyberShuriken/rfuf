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
	"github.com/CyberShuriken/rfuf/internal/scope"
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
		if !strings.Contains(step.Command, "[ -f amass_raw.txt ] || touch amass_raw.txt") {
			t.Fatalf("amass_enum must create the artifact when exit 0 produces no file: %q", step.Command)
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

func TestValidateResumeScopeRequiresMatchingMode(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "scope.json"), []byte(`{"input":"*.example.com","root_domain":"example.com","mode":"wildcard"}`), 0644); err != nil {
		t.Fatal(err)
	}
	exact, err := scope.Parse("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateResumeScope(dir, exact); err == nil || !strings.Contains(err.Error(), "existing scan is wildcard mode") {
		t.Fatalf("expected exact/wildcard mismatch, got %v", err)
	}
	wildcard, err := scope.Parse("*.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateResumeScope(dir, wildcard); err != nil {
		t.Fatalf("matching wildcard scope rejected: %v", err)
	}
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
	for _, step := range GetSteps("*.example.com", &config.Paths{}) {
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

func TestScopeGuardCreatesDeclaredArtifacts(t *testing.T) {
	var command string
	for _, step := range GetSteps("admin.wickr.com", &config.Paths{}) {
		if step.ID == "scope_guard" {
			command = step.Command
			break
		}
	}
	if command == "" {
		t.Fatal("scope_guard step not found")
	}
	if !strings.Contains(command, "touch scope.json in_scope_hosts.txt out_of_scope_hosts.txt scoped_subs.txt") {
		t.Fatalf("scope_guard must materialize every declared artifact: %q", command)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "subs.txt"), []byte("admin.wickr.com\napi.admin.wickr.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", command)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"RFUF_DOMAIN=admin.wickr.com",
		"RFUF_SCOPE_INPUT=admin.wickr.com",
		"RFUF_SCOPE_MODE=exact",
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("scope_guard failed: %v output=%s", err, output)
	}
	for _, name := range []string{"scope.json", "in_scope_hosts.txt", "out_of_scope_hosts.txt", "scoped_subs.txt"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("scope_guard did not create %s: %v", name, err)
		}
	}
	inScope, err := os.ReadFile(filepath.Join(dir, "in_scope_hosts.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(inScope)) != "admin.wickr.com" {
		t.Fatalf("exact scope accepted unexpected hosts: %q", inScope)
	}
}

func TestEnsureZeroResultArtifacts(t *testing.T) {
	dir := t.TempDir()
	outputs := []string{"scope.json", "in_scope_hosts.txt", "out_of_scope_hosts.txt", "scoped_subs.txt"}
	if err := ensureZeroResultArtifacts(dir, "scope_guard", outputs); err != nil {
		t.Fatal(err)
	}
	jsOutputs := []string{"js_assets.txt", "js_endpoints.txt", "jsmap_status.txt"}
	if err := ensureZeroResultArtifacts(dir, "jsmap_scrape", jsOutputs); err != nil {
		t.Fatal(err)
	}
	for _, name := range append(outputs, jsOutputs...) {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("missing materialized artifact %s: %v", name, err)
		}
		if info.Size() != 0 {
			t.Fatalf("materialized artifact %s is not empty", name)
		}
	}
	if err := ensureZeroResultArtifacts(dir, "httpx_probe", []string{"alive.txt"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "alive.txt")); !os.IsNotExist(err) {
		t.Fatalf("non-discovery stage unexpectedly materialized an artifact: %v", err)
	}
}

func TestScopeGuardCreatesArtifactsWithoutInput(t *testing.T) {
	var command string
	for _, step := range GetSteps("admin.wickr.com", &config.Paths{}) {
		if step.ID == "scope_guard" {
			command = step.Command
			break
		}
	}
	if command == "" {
		t.Fatal("scope_guard step not found")
	}
	dir := t.TempDir()
	cmd := exec.Command("bash", "-c", command)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"RFUF_DOMAIN=admin.wickr.com",
		"RFUF_SCOPE_INPUT=admin.wickr.com",
		"RFUF_SCOPE_MODE=exact",
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("scope_guard failed without input: %v output=%s", err, output)
	}
	for _, name := range []string{"scope.json", "in_scope_hosts.txt", "out_of_scope_hosts.txt", "scoped_subs.txt"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("scope_guard did not create %s without input: %v", name, err)
		}
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

// TestRunForScopeDashboardStartTimeResetsOnFreshRerun guards against the
// "dashboard shows the previous run's elapsed time" bug. The dashboard
// computes elapsed = time.Since(startTime), and startTime must come from
// cp.StartedAt AFTER any checkpoint.Reset() call — otherwise re-running
// rfuf against an existing work dir without -resume displays wall-clock
// elapsed from the previous invocation.
//
// We model the lifecycle directly (load → reset → re-read) instead of
// running the whole pipeline so the test stays fast and deterministic.
func TestRunForScopeDashboardStartTimeResetsOnFreshRerun(t *testing.T) {
	dir := t.TempDir()

	// First run: load + complete one step + save. cp.StartedAt is "old".
	cp, err := checkpoint.Load(dir, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	oldStart := cp.StartedAt
	if err := cp.CompleteStep("subfinder"); err != nil {
		t.Fatal(err)
	}
	// Force a clearly-old wall-clock value so the assertion below is
	// unambiguous — we'd otherwise be racing against time.Now() at the
	// millisecond granularity of test scheduling.
	past := time.Now().Add(-72 * time.Hour)
	cp.StartedAt = past
	if err := cp.Save(); err != nil {
		t.Fatal(err)
	}

	// Second run (no -resume): reload, observe CompletedSteps > 0, reset.
	cp2, err := checkpoint.Load(dir, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(cp2.CompletedSteps) == 0 {
		t.Fatal("setup: expected CompletedSteps to carry across reload")
	}
	if !cp2.StartedAt.Equal(past) {
		t.Fatalf("setup: expected loaded StartedAt to equal past, got %v want %v", cp2.StartedAt, past)
	}

	// Reproduce the fixed pipeline shape: read cp.StartedAt, then if not
	// resuming and CompletedSteps>0, Reset(), then re-read cp.StartedAt.
	startTime := cp2.StartedAt
	if len(cp2.CompletedSteps) > 0 {
		if err := cp2.Reset(); err != nil {
			t.Fatal(err)
		}
		startTime = cp2.StartedAt
	}

	// After reset, startTime must be recent — not the 72h-old value.
	if startTime.Equal(oldStart) || startTime.Equal(past) {
		t.Fatalf("startTime still points at the previous run: %v", startTime)
	}
	if d := time.Since(startTime); d < 0 || d > 5*time.Second {
		t.Fatalf("startTime should be within the last few seconds, got %v ago", d)
	}
}

// TestRunForScopeDashboardStartTimePreservedOnResume confirms the inverse:
// when -resume is set the original StartedAt must survive untouched, so
// elapsed reflects total work across the original run plus the resumed
// session.
func TestRunForScopeDashboardStartTimePreservedOnResume(t *testing.T) {
	dir := t.TempDir()
	cp, err := checkpoint.Load(dir, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := cp.CompleteStep("subfinder"); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-48 * time.Hour)
	cp.StartedAt = past
	if err := cp.Save(); err != nil {
		t.Fatal(err)
	}

	cp2, err := checkpoint.Load(dir, "example.com")
	if err != nil {
		t.Fatal(err)
	}

	// Resume path: do NOT reset; the existing StartedAt is the truth.
	startTime := cp2.StartedAt
	if !startTime.Equal(past) {
		t.Fatalf("resume path lost original StartedAt: got %v want %v", startTime, past)
	}
}

// TestMergeBruteSubsPassesWhenBruteSubsEmpty reproduces the exact wolt.com
// failure: exact-mode scan where subdomain_brute exits 0 with an empty
// brute_subs.txt, then merge_brute_subs runs `cat … | sort -u > tmp && mv
// tmp live_subs.txt`. Before the extractor fix, the coverage check only
// saw the redirect target (the renamed-away tmp file) and flagged the
// step as status=failed despite exit_code=0. After the fix, the step must
// record live_subs.txt as an output and complete successfully (or
// completed_empty if scoped_subs.txt was also empty).
func TestMergeBruteSubsPassesWhenBruteSubsEmpty(t *testing.T) {
	var command string
	for _, step := range GetSteps("wolt.com", &config.Paths{}) {
		if step.ID == "merge_brute_subs" {
			command = step.Command
			break
		}
	}
	if command == "" {
		t.Fatal("merge_brute_subs step not found")
	}

	// Exact-mode fixture: scoped_subs.txt has the apex, brute_subs.txt
	// is empty (subdomain_brute exits 0 immediately in exact mode).
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "scoped_subs.txt"), []byte("wolt.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "brute_subs.txt"), nil, 0644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("bash", "-c", command)
	cmd.Dir = dir
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("merge_brute_subs failed to execute: %v output=%s", err, output)
	}

	// The post-condition: live_subs.txt must contain the merged result.
	data, err := os.ReadFile(filepath.Join(dir, "live_subs.txt"))
	if err != nil {
		t.Fatalf("live_subs.txt missing after merge_brute_subs: %v", err)
	}
	if !strings.Contains(string(data), "wolt.com") {
		t.Fatalf("live_subs.txt missing apex after merge: %q", data)
	}

	// Coverage check must see live_subs.txt as an output and report
	// Exists=true — this is the assertion the bug used to break.
	outputs := coverage.ExtractOutputPaths(command)
	var found bool
	for _, p := range outputs {
		if p == "live_subs.txt" {
			found = true
		}
	}
	if !found {
		t.Fatalf("ExtractOutputPaths did not capture live_subs.txt from %q; got %v", command, outputs)
	}
	metrics := coverage.MeasureArtifacts(dir, outputs)
	for _, m := range metrics {
		if m.Path == "live_subs.txt" && !m.Exists {
			t.Fatalf("live_subs.txt reported missing despite existing: %+v", metrics)
		}
	}
}

// TestMergeBruteSubsPassesWhenScopedSubsEmpty covers the rarer both-empty
// case: if scoped_subs.txt is empty AND brute_subs.txt is empty (a zero-
// result exact-mode scan with no upstream discovery), merge_brute_subs
// still must materialize live_subs.txt so downstream stages don't see a
// missing file.
func TestMergeBruteSubsPassesWhenScopedSubsEmpty(t *testing.T) {
	var command string
	for _, step := range GetSteps("wolt.com", &config.Paths{}) {
		if step.ID == "merge_brute_subs" {
			command = step.Command
			break
		}
	}
	if command == "" {
		t.Fatal("merge_brute_subs step not found")
	}

	dir := t.TempDir()
	// Both inputs empty.
	if err := os.WriteFile(filepath.Join(dir, "scoped_subs.txt"), nil, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "brute_subs.txt"), nil, 0644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("bash", "-c", command)
	cmd.Dir = dir
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("merge_brute_subs failed to execute on empty inputs: %v output=%s", err, output)
	}

	if _, err := os.Stat(filepath.Join(dir, "live_subs.txt")); err != nil {
		t.Fatalf("live_subs.txt missing after zero-input merge_brute_subs: %v", err)
	}

	if err := ensureZeroResultArtifacts(dir, "merge_brute_subs", []string{"live_subs.txt"}); err != nil {
		t.Fatalf("ensureZeroResultArtifacts rejected merge_brute_subs: %v", err)
	}
}

// TestDirbruteFFUFPassesWhenAliveEmpty reproduces the dirbrute_ffuf failure
// mode seen in the wolt.com run: when alive.txt is empty (no live hosts
// from httpx_probe), the step's else-branch runs `: > ffuf_dirs_raw.txt`
// but ffuf_results/all.json is NEVER created, so the coverage checker
// sees a missing declared output and marks the step status=failed
// despite exit_code=0. After the fix, ensureZeroResultArtifacts must
// materialize ffuf_results/all.json so the step is reported
// completed_empty.
func TestDirbruteFFUFPassesWhenAliveEmpty(t *testing.T) {
	var command string
	for _, step := range GetSteps("wolt.com", &config.Paths{}) {
		if step.ID == "dirbrute_ffuf" {
			command = step.Command
			break
		}
	}
	if command == "" {
		t.Fatal("dirbrute_ffuf step not found")
	}

	// Zero-alive fixture: alive.txt is empty, which sends the step down
	// the `: > ffuf_dirs_raw.txt` else-branch.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "alive.txt"), nil, 0644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("bash", "-c", command)
	cmd.Dir = dir
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("dirbrute_ffuf failed to execute: %v output=%s", err, output)
	}

	// The shell correctly created ffuf_dirs_raw.txt, but did NOT create
	// ffuf_results/all.json (it only exists in the happy path). The
	// pipeline's post-execute step calls ensureZeroResultArtifacts
	// exactly to fill that gap; we run it here to verify.
	_, outputs := stageArtifacts(Step{ID: "dirbrute_ffuf", Command: command})
	if err := ensureZeroResultArtifacts(dir, "dirbrute_ffuf", outputs); err != nil {
		t.Fatalf("ensureZeroResultArtifacts rejected dirbrute_ffuf: %v", err)
	}

	// Both declared outputs must now exist.
	if _, err := os.Stat(filepath.Join(dir, "ffuf_dirs_raw.txt")); err != nil {
		t.Fatalf("ffuf_dirs_raw.txt missing after ensureZeroResultArtifacts: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ffuf_results", "all.json")); err != nil {
		t.Fatalf("ffuf_results/all.json missing after ensureZeroResultArtifacts: %v", err)
	}

	// Coverage must see all declared outputs as Exists=true.
	metrics := coverage.MeasureArtifacts(dir, outputs)
	for _, m := range metrics {
		if !m.Exists {
			t.Fatalf("output %s reported missing despite existing: %+v", m.Path, metrics)
		}
	}
}

// TestWafDetectPassesWhenWafw00fMissing reproduces the waf_detect failure
// mode seen in the wolt.com run: the previous step's command created
// waf_targets_tmp.txt via `> waf_targets_tmp.txt`, ran wafw00f, and then
// `rm -f waf_targets_tmp.txt` removed it. The coverage extractor sees the
// redirect as a declared output, the post-run measurement sees the file
// missing, and the step is marked status=failed despite exit_code=0.
// After the fix (no rm, plus else-branch materialization), the file
// must exist after the step runs.
func TestWafDetectPassesWhenWafw00fMissing(t *testing.T) {
	var command string
	for _, step := range GetSteps("wolt.com", &config.Paths{}) {
		if step.ID == "waf_detect" {
			command = step.Command
			break
		}
	}
	if command == "" {
		t.Fatal("waf_detect step not found")
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "alive.txt"), nil, 0644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("bash", "-c", command)
	cmd.Dir = dir
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("waf_detect failed to execute: %v output=%s", err, output)
	}

	// The fix: when wafw00f is missing, the else-branch must materialize
	// BOTH waf_targets_tmp.txt and waf_detections.txt so the step
	// reports completed_empty instead of failed.
	if _, err := os.Stat(filepath.Join(dir, "waf_targets_tmp.txt")); err != nil {
		t.Fatalf("waf_targets_tmp.txt missing after waf_detect: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "waf_detections.txt")); err != nil {
		t.Fatalf("waf_detections.txt missing after waf_detect: %v", err)
	}

	// The command must NOT contain `rm -f waf_targets_tmp.txt` — that
	// is the line that caused the bug in the first place. If this
	// assertion ever fires, the regression has been reintroduced.
	if strings.Contains(command, "rm -f waf_targets_tmp.txt") {
		t.Fatalf("waf_detect command still removes its own declared output: %s", command)
	}
}

// TestMergeJSEndpointsPasses verifies the same bug shape on
// merge_js_endpoints, which also uses `> tmp && mv tmp dst`. If the
// extractor only sees the redirect target (renamed-away tmp), the step
// is wrongly flagged status=failed.
func TestMergeJSEndpointsPasses(t *testing.T) {
	var command string
	for _, step := range GetSteps("wolt.com", &config.Paths{}) {
		if step.ID == "merge_js_endpoints" {
			command = step.Command
			break
		}
	}
	if command == "" {
		t.Fatal("merge_js_endpoints step not found")
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "js_endpoints.txt"), []byte("https://app.wolt.com/api\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "all_urls.txt"), []byte("https://app.wolt.com/home\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("bash", "-c", command)
	cmd.Dir = dir
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("merge_js_endpoints failed: %v output=%s", err, output)
	}

	data, err := os.ReadFile(filepath.Join(dir, "all_urls.txt"))
	if err != nil {
		t.Fatalf("all_urls.txt missing after merge: %v", err)
	}
	if !strings.Contains(string(data), "app.wolt.com") {
		t.Fatalf("all_urls.txt missing endpoints after merge: %q", data)
	}

	outputs := coverage.ExtractOutputPaths(command)
	var found bool
	for _, p := range outputs {
		if p == "all_urls.txt" {
			found = true
		}
	}
	if !found {
		t.Fatalf("ExtractOutputPaths did not capture all_urls.txt from merge_js_endpoints; got %v", outputs)
	}
}
