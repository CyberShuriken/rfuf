package findings

import (
	"os"
	"path/filepath"
	"testing"
)

// Each new active scanner must run cleanly on an empty work dir and create its
// declared output file(s) — otherwise the pipeline stage contract fails at
// runtime (the class of bug the mobile_recon "." input caused). This drives all
// seven through RunFinder with an empty corpus and asserts outputs exist.
func TestNewScannersEmptyWorkdirCreateOutputs(t *testing.T) {
	os.Setenv("RFUF_SCOPE_INPUT", "*.example.com")
	defer os.Unsetenv("RFUF_SCOPE_INPUT")

	cases := map[string][]string{
		"protopollution": {"prototype_pollution_findings.txt", "prototype_pollution_candidates.txt"},
		"ssti":           {"ssti_findings.txt", "ssti_candidates.txt"},
		"nosqli":         {"nosqli_findings.txt", "nosqli_candidates.txt"},
		"cachepoison":    {"cache_poisoning_findings.txt", "cache_poisoning_candidates.txt"},
		"xxe":            {"xxe_findings.txt", "xxe_candidates.txt"},
		"csrf":           {"csrf_candidates.txt"},
		"smuggling":      {"http_smuggling_candidates.txt"},
	}
	for finder, outputs := range cases {
		work := t.TempDir()
		// Empty inputs — exercises the zero-result path.
		for _, f := range []string{"all_urls_200.txt", "alive.txt"} {
			if err := os.WriteFile(filepath.Join(work, f), nil, 0644); err != nil {
				t.Fatal(err)
			}
		}
		if err := RunFinder(finder, work); err != nil {
			t.Errorf("%s RunFinder on empty workdir: %v", finder, err)
			continue
		}
		for _, o := range outputs {
			if _, err := os.Stat(filepath.Join(work, o)); err != nil {
				t.Errorf("%s did not create declared output %s: %v", finder, o, err)
			}
		}
	}
}
