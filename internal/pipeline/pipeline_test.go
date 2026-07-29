package pipeline

import (
	"strings"
	"testing"

	"github.com/CyberShuriken/rfuf/internal/config"
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
		if !strings.Contains(step.Command, "dalfox pipe --output xss_vulnerabilities.txt") {
			t.Fatalf("xss_scan has unexpected Dalfox command: %q", step.Command)
		}
		return
	}

	t.Fatal("xss_scan step not found")
}

// TestDirbruteUsesRecursion guards against the slow per-host loop
// regressing back in. The fast path is one ffuf invocation with two
// wordlists (-w hosts.txt:HOST + -w words.txt:WORD), recursion enabled,
// and a 10-minute cap. Per-host bash loops are forbidden.
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
	if !strings.Contains(cmd, "-recursion-depth 2") {
		t.Errorf("dirbrute_ffuf missing -recursion-depth 2: %q", cmd)
	}
	if !strings.Contains(cmd, "-maxtime 600") {
		t.Errorf("dirbrute_ffuf missing -maxtime 600 (will hang on big wordlists): %q", cmd)
	}
	if !strings.Contains(cmd, "alive.txt:HOST") {
		t.Errorf("dirbrute_ffuf should use two-wordlist mode (-w alive.txt:HOST): %q", cmd)
	}
	if strings.Contains(cmd, "while read") {
		t.Errorf("dirbrute_ffuf regressed to per-host bash loop: %q", cmd)
	}
}

// TestUrlFilterAliveExists ensures the 200-only filter step is wired
// into the pipeline. Without it, downstream vuln scanners (sqlmap,
// dalfox, nuclei) waste time on dead URLs from gau/wayback.
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
		t.Errorf("url_filter_alive must use httpx -mc 200: %q", cmd)
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
func TestVulnTargetsSourceFrom200Only(t *testing.T) {
	steps := GetSteps("example.com", &config.Paths{})
	scanSteps := []string{
		"sqli_targets", "xss_targets", "rce_targets",
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
				if d == "url_filter_alive" {
					depOK = true
					break
				}
			}
			if !depOK {
				t.Errorf("%s must depend on url_filter_alive, deps=%v", want, s.Deps)
			}
			break
		}
		if !found {
			t.Errorf("%s step missing", want)
		}
	}
}
