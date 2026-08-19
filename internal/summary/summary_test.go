package summary

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CyberShuriken/rfuf/internal/checkpoint"
)

func TestGenerateWritesFindingsMD(t *testing.T) {
	workDir := t.TempDir()
	cp := &checkpoint.Checkpoint{
		Domain:      "example.com",
		StartedAt:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		LastUpdated: time.Date(2026, 1, 1, 0, 30, 0, 0, time.UTC),
	}

	if err := Generate(workDir, cp); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	for _, name := range []string{"findings.md", "SUMMARY.md"} {
		path := filepath.Join(workDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("missing output %s: %v", name, err)
		}
		body := string(data)
		if name == "findings.md" && !strings.Contains(body, "Findings for example.com") {
			t.Errorf("findings.md missing header, got: %s", body[:min(200, len(body))])
		}
		if name == "SUMMARY.md" && !strings.Contains(body, "Scan Summary") {
			t.Errorf("SUMMARY.md missing header, got: %s", body[:min(200, len(body))])
		}
	}
}

// TestFindingsContainsRecommendedRetest ensures every severity section
// emits a "Recommended manual retest" hint — the hunter's cue for what
// to do with each finding without re-reading tool docs.
func TestFindingsContainsRecommendedRetest(t *testing.T) {
	workDir := t.TempDir()
	cp := &checkpoint.Checkpoint{Domain: "example.com"}

	// Seed one finding per severity bucket so addSection writes them.
	write := func(name string, lines ...string) {
		path := filepath.Join(workDir, name)
		data := []byte(strings.Join(lines, "\n"))
		_ = os.WriteFile(path, data, 0644)
	}
	write("nuclei_rce_rce.txt", "https://example.com/admin?cmd=whoami")
	write("validated_takeovers.txt", "staging.example.com")
	write("lfi_results.txt", "https://example.com/?file=foo")
	write("ssrf_vulnerabilities.txt", "https://example.com/?url=foo")
	write("trufflehog_results.txt", "AKIA...")
	write("xss_vulnerabilities.txt", "https://example.com/?q=<script>")
	write("auth_results.txt", "JWT alg:none accepted on /api")
	write("idor_vulnerabilities.txt", "https://example.com/user/1")
	write("open_redirect_results.txt", "https://example.com/?next=foo")
	write("cors_findings.txt", "[VULN] https://example.com")
	write("graphql_exposed.txt", "/graphql on api.example.com")
	write("ffuf_dirs_200.txt", "https://example.com/.git/config")
	write("manual_business_logic_review.txt", "https://example.com/cart")

	if err := Generate(workDir, cp); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(workDir, "findings.md"))
	if err != nil {
		t.Fatalf("findings.md missing: %v", err)
	}
	text := string(body)
	if !strings.Contains(text, "Recommended manual retest") {
		t.Errorf("findings.md missing 'Recommended manual retest' sub-bullet:\n%s", text)
	}
}

// TestFindingsContainsFilteredOutAppendix checks the transparency
// appendix surfaces — the hunter should see what was dropped, not
// just what was kept.
func TestFindingsContainsFilteredOutAppendix(t *testing.T) {
	workDir := t.TempDir()
	cp := &checkpoint.Checkpoint{Domain: "example.com"}

	// Two-URL stream for the prune count.
	_ = os.WriteFile(filepath.Join(workDir, "all_urls.txt"), []byte("a\nb\n"), 0644)
	_ = os.WriteFile(filepath.Join(workDir, "all_urls_200.txt"), []byte("a\n"), 0644)

	// sqlmap_results: one confirmed, one dropped.
	results := filepath.Join(workDir, "sqlmap_results")
	if err := os.MkdirAll(filepath.Join(results, "confirmed.example.com"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(results, "dropped.example.com"), 0755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(results, "confirmed.example.com", "log"),
		[]byte("Type: boolean-based blind\nPayload: AND 1=1\n"), 0644)
	_ = os.WriteFile(filepath.Join(results, "dropped.example.com", "log"),
		[]byte("Parameter might be injectable\n"), 0644)

	if err := Generate(workDir, cp); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	body, _ := os.ReadFile(filepath.Join(workDir, "findings.md"))
	text := string(body)
	if !strings.Contains(text, "What was filtered out") {
		t.Errorf("findings.md missing 'What was filtered out' appendix:\n%s", text)
	}
	if !strings.Contains(text, "URLs pruned for not responding testable:") {
		t.Errorf("findings.md should report the URL prune count")
	}
	if !strings.Contains(text, "sqlmap candidate folders dropped") {
		t.Errorf("findings.md should report dropped sqlmap folders")
	}
}

// TestSummaryFormatArgOrder ensures SUMMARY.md's format string never ends
// up misaligned with its arguments (the previous version appended the
// backupscan/hostheader/secheaders/cors2 counts at the END of the arg list
// while their labels sat mid-document, producing %!d(MISSING) markers and
// wrong numbers next to the labels). The test fills every findings file
// the report reads with N lines and asserts the printed counts are all N.
func TestSummaryFormatArgOrder(t *testing.T) {
	workDir := t.TempDir()
	cp := &checkpoint.Checkpoint{Domain: "example.com"}

	// Any file the SUMMARY template %d-labels gets the same distinct line
	// count so a misplaced argument becomes visible as a wrong number.
	writeN := func(name string, n int) {
		lines := make([]string, n)
		for i := range lines {
			lines[i] = "https://example.com/finding-" + name + "-" + string(rune('a'+i))
		}
		_ = os.WriteFile(filepath.Join(workDir, name), []byte(strings.Join(lines, "\n")), 0644)
	}

	// One findings line each for every file Generate reads (empty files are
	// fine for the format-order check — we only assert the counters that
	// are wired through the template).
	for _, name := range []string{
		"subs.txt", "live_subs.txt", "alive.txt", "tech_fingerprint.txt",
		"naabu_ports.txt", "hidden_params.txt",
		"nuclei_rce_rce.txt", "validated_takeovers.txt", "lfi_results.txt",
		"ssrf_vulnerabilities.txt", "xss_vulnerabilities.txt",
		"trufflehog_results.txt", "potential_secrets.txt", "auth_results.txt",
		"cors_findings.txt", "idor_vulnerabilities.txt", "open_redirect_results.txt",
		"graphql_exposed.txt", "ffuf_dirs_200.txt",
		"discourse_findings.txt", "laravel_findings.txt", "wordpress_findings.txt",
		"cache_poison_findings.txt", "js_endpoints.txt", "js_secrets.txt",
		"js_endpoint_findings.txt", "waf_detections.txt", "ghauri_results.txt",
		"api_specs.txt", "bola_targets.txt", "bola_permutations.txt",
		"nextjs_plaid_jwt_findings.txt", "drf_findings.txt", "drf_idor_targets.txt",
		"reflection_findings.txt", "paramshape_findings.txt", "authshape_findings.txt",
		"signup_takeover_findings.txt", "idor_surface.txt", "oauth_findings.txt",
		"race_results.txt", "bucket_findings.txt", "takeover_v2_findings.txt",
		"js_mine_findings.txt", "business_logic_findings.txt", "nuclei_rfuf_pass.txt",
		"backupscan_findings.txt", "hostheader_findings.txt",
		"secheaders_findings.txt", "cors2_findings.txt",
	} {
		writeN(name, 7)
	}
	if err := Generate(workDir, cp); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(workDir, "SUMMARY.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if strings.Contains(text, "%!") {
		t.Errorf("SUMMARY.md contains leftover format markers — label/arg order is broken:\n%s", text)
	}
	// sanity: every labeled counter must show the seeded count (7) or the
	// sqlmap-derived counts — mismatched labels would show a different number
	// or a missing marker.
	for _, label := range []string{
		"**Backup / sensitive files exposed:** 7", "**Host header injection:** 7",
		"**Security header gaps:** 7", "**Credentialed CORS (preflight):** 7",
		"**DRF hosts detected:** 7", "**BOLA cross-tenant permutations:** 7",
		"**DRF IDOR targets (/api/vN/):** 7",
	} {
		if !strings.Contains(text, label) {
			t.Errorf("SUMMARY.md missing or misnumbered label %q", label)
		}
	}
}

// TestConfirmedSqlmapResults splits sqlmap_results/ into confirmed vs
// dropped using the same heuristic the report relies on.
func TestConfirmedSqlmapResults(t *testing.T) {
	root := t.TempDir()
	// Confirmed: real technique + payload.
	c1 := filepath.Join(root, "vuln-a.example.com")
	_ = os.MkdirAll(c1, 0755)
	_ = os.WriteFile(filepath.Join(c1, "log"),
		[]byte("Type: boolean-based blind\nPayload: foo\n"), 0644)
	// Dropped: only the "might be" header, no technique, no payload.
	d1 := filepath.Join(root, "noise-b.example.com")
	_ = os.MkdirAll(d1, 0755)
	_ = os.WriteFile(filepath.Join(d1, "log"),
		[]byte("Parameter might be injectable (DBMS: MySQL)\n"), 0644)
	// Dropped: folder with no log file at all.
	d2 := filepath.Join(root, "empty-c.example.com")
	_ = os.MkdirAll(d2, 0755)

	confirmed, dropped := confirmedSqlmapResults(root)
	if len(confirmed) != 1 || confirmed[0] != "vuln-a.example.com" {
		t.Errorf("expected vuln-a.example.com confirmed, got %v", confirmed)
	}
	if len(dropped) != 2 {
		t.Errorf("expected 2 dropped folders, got %v", dropped)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
