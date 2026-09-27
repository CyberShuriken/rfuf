package scope

import "testing"

func TestParsePreservesScopeMode(t *testing.T) {
	cases := []struct {
		input string
		root  string
		mode  Mode
	}{
		{input: "example.com", root: "example.com", mode: ExactMode},
		{input: "*.Example.COM.", root: "example.com", mode: WildcardMode},
		{input: "  api.example.com ", root: "api.example.com", mode: ExactMode},
	}
	for _, tc := range cases {
		got, err := Parse(tc.input)
		if err != nil {
			t.Fatalf("Parse(%q) returned error: %v", tc.input, err)
		}
		if got.RootDomain != tc.root || got.Mode != tc.mode {
			t.Fatalf("Parse(%q) = root=%q mode=%q, want root=%q mode=%q", tc.input, got.RootDomain, got.Mode, tc.root, tc.mode)
		}
	}
}

func TestNormalizeDomain(t *testing.T) {
	for input, want := range map[string]string{
		"example.com":        "example.com",
		"*.Example.COM.":     "example.com",
		"  api.example.com ": "api.example.com",
	} {
		got, err := NormalizeDomain(input)
		if err != nil {
			t.Fatalf("NormalizeDomain(%q) returned error: %v", input, err)
		}
		if got != want {
			t.Fatalf("NormalizeDomain(%q) = %q, want %q", input, got, want)
		}
	}
	for _, input := range []string{"", "example", "https://example.com", "example.com/path", "127.0.0.1", "*.", "foo.*.example.com"} {
		if _, err := NormalizeDomain(input); err == nil {
			t.Errorf("NormalizeDomain(%q) accepted invalid scope", input)
		}
	}
}

func TestExactScopeIncludesOnlyRoot(t *testing.T) {
	parsed, err := Parse("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.IncludesHost("https://example.com/v1") {
		t.Error("exact scope rejected its root host")
	}
	for _, host := range []string{"www.example.com", "api.v1.example.com", "example.com.evil.test", "notexample.com"} {
		if parsed.IncludesHost(host) {
			t.Errorf("exact scope accepted %q", host)
		}
	}
}

func TestWildcardScopeIncludesProperSubdomains(t *testing.T) {
	parsed, err := Parse("*.example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"example.com", "www.example.com", "api.v1.example.com", "https://API.Example.com/v1"} {
		if !parsed.IncludesHost(host) {
			t.Errorf("wildcard scope rejected %q", host)
		}
	}
	for _, host := range []string{"example.com.evil.test", "notexample.com", "evil-example.com", "https://example.com.evil.test/path"} {
		if parsed.IncludesHost(host) {
			t.Errorf("wildcard scope accepted %q", host)
		}
	}
}

func TestFilterLinesPreservesMode(t *testing.T) {
	lines := []string{
		"https://www.example.com/a",
		"https://example.com",
		"https://example.com.evil.test",
		"https://third-party.test/script.js",
	}
	in, out, err := FilterLines(lines, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(in) != 1 || len(out) != 3 {
		t.Fatalf("exact FilterLines returned %d in-scope and %d out-of-scope lines, want 1 and 3", len(in), len(out))
	}
	in, out, err = FilterLines(lines, "*.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(in) != 2 || len(out) != 2 {
		t.Fatalf("wildcard FilterLines returned %d in-scope and %d out-of-scope lines, want 2 and 2", len(in), len(out))
	}
}

func TestCanonicalizeStreamNormalizesScopesDeduplicatesAndCaps(t *testing.T) {
	scanScope, err := Parse("*.fixture.test")
	if err != nil {
		t.Fatal(err)
	}
	lines := []string{
		"HTTPS://API.FIXTURE.TEST:443/path#fragment",
		"https://api.fixture.test/path",
		"https://app.fixture.test/private",
		"https://outside.test/path",
		"not a URL",
		"https://other.fixture.test/one",
	}
	got, counts, err := CanonicalizeStream(lines, "fixture", scanScope, `/private`, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Value != "https://api.fixture.test/path" {
		t.Fatalf("canonical targets = %#v", got)
	}
	if len(got[0].Sources) != 1 || got[0].Sources[0] != "fixture" {
		t.Fatalf("provenance missing: %#v", got[0])
	}
	if counts.Input != 6 || counts.InScope != 4 || counts.Excluded != 1 || counts.OutOfScope != 1 || counts.Duplicate != 1 || counts.Capped != 1 || counts.Invalid != 1 || counts.Final != 1 {
		t.Fatalf("unexpected canonical stream counts: %+v", counts)
	}
}

func TestCanonicalizeStreamExplainsEmptyResults(t *testing.T) {
	scanScope, _ := Parse("example.test")
	_, counts, err := CanonicalizeStream(nil, "empty", scanScope, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	if counts.Reason != "no_input" || counts.Final != 0 {
		t.Fatalf("empty stream reason=%q counts=%+v", counts.Reason, counts)
	}
}
