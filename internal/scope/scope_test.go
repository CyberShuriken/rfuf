package scope

import "testing"

func TestNormalizeDomain(t *testing.T) {
	cases := map[string]string{
		"example.com":        "example.com",
		"*.Example.COM.":     "example.com",
		"  api.example.com ": "api.example.com",
	}
	for input, want := range cases {
		got, err := NormalizeDomain(input)
		if err != nil {
			t.Fatalf("NormalizeDomain(%q) returned error: %v", input, err)
		}
		if got != want {
			t.Fatalf("NormalizeDomain(%q) = %q, want %q", input, got, want)
		}
	}
	for _, input := range []string{"", "example", "https://example.com", "example.com/path", "127.0.0.1", "*."} {
		if _, err := NormalizeDomain(input); err == nil {
			t.Errorf("NormalizeDomain(%q) accepted invalid scope", input)
		}
	}
}

func TestInScopeHost(t *testing.T) {
	root := "example.com"
	positive := []string{"example.com", "www.example.com", "api.v1.example.com", "https://API.Example.com/v1"}
	negative := []string{"example.com.evil.test", "notexample.com", "evil-example.com", "https://example.com.evil.test/path"}
	for _, host := range positive {
		if !InScopeHost(host, root) {
			t.Errorf("InScopeHost(%q) = false, want true", host)
		}
	}
	for _, host := range negative {
		if InScopeHost(host, root) {
			t.Errorf("InScopeHost(%q) = true, want false", host)
		}
	}
}

func TestFilterLines(t *testing.T) {
	in, out, err := FilterLines([]string{
		"https://www.example.com/a",
		"https://www.example.com/a",
		"https://example.com",
		"https://example.com.evil.test",
		"https://third-party.test/script.js",
	}, "*.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(in) != 2 || len(out) != 2 {
		t.Fatalf("FilterLines returned %d in-scope and %d out-of-scope lines, want 2 and 2", len(in), len(out))
	}
}
