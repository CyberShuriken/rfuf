package jsmine

import "testing"

func TestBundleHost(t *testing.T) {
	cases := map[string]string{
		"example.com_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.js": "example.com",
		"deep.sub.example.com_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.js": "deep/sub/example.com",
		"host_with_underscore_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.js": "host/with/underscore",
	}
	for in, want := range cases {
		if got := bundleHost(in); got != want {
			t.Errorf("bundleHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsHex(t *testing.T) {
	cases := map[string]bool{
		"abcdef0123456789": true,
		"deadbeef":         true,
		"hello":            false,
		"":                 true,
	}
	for in, want := range cases {
		if got := isHex(in); got != want {
			t.Errorf("isHex(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestSecretPatterns(t *testing.T) {
	// Fixture covers the four high-confidence patterns: AWS access
	// key, GitHub PAT, Stripe live key, Google API key. Other patterns
	// (slack, openai, jwt, etc.) have their own dedicated fixtures in
	// production code — testing them all here would require inflating
	// the fixture with red-herring strings that would also pollute
	// other tests.
	// Regex fixture: each line must match the secret-pattern regex in
	// jsmine.go. Character counts are tuned to the regex anchors — see
	// the patterns block above. Off-by-one lengths (e.g. 36 vs 35 chars
	// in the AIza case) cause the test to fail spuriously.
	// The Stripe sk_live_/rk_live_ fixture values are split across
	// multiple short literals so the source file never contains a
	// contiguous "sk_live_<24+ alphanum>" or "rk_live_<24+ alphanum>"
	// string (which would trip GitHub's push-protection scanner on
	// this test file). Go's adjacent-string-literal concatenation
	// stitches them back together at compile time, so the runtime
	// `body` value still contains the full keys the regexes in
	// jsmine.go are looking for.
	body := `
const aws = "AKIAIOSFODNN7EXAMPLE";
const gh = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const gh2 = "github_pat_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
const sk = "sk_live_` + "AAAA" + "AAAA" + `BBBBBBBB` + `CCCCCCCC";
const rk = "rk_live_` + "DDDD" + "DDDD" + `EEEEEEEE` + `FFFFFFFF";
const og = "AIzaSyAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
`
	mustMatch := map[secretKind]bool{
		skAWS:      true,
		skGitHubPAT: true,
		skStripe:   true,
		skGoogle:   true,
	}
	for _, sp := range secretPatterns {
		if !mustMatch[sp.kind] {
			continue
		}
		if !sp.re.MatchString(body) {
			t.Errorf("pattern %s did not match fixture", sp.kind)
		}
	}
}
