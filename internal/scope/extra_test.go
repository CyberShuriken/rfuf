package scope

import "testing"

func TestIncludesHostWithExtraRoots(t *testing.T) {
	base, err := Parse("saytechnologies.com") // exact
	if err != nil {
		t.Fatal(err)
	}
	s, err := base.WithExtraRoots([]string{"*.robinhood.com", "# a comment", "", "example.org"})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"saytechnologies.com":     true,  // primary (exact)
		"app.saytechnologies.com": false, // primary is exact — subdomain excluded
		"robinhood.com":           true,  // extra wildcard root
		"api.robinhood.com":       true,  // extra wildcard subdomain
		"example.org":             true,  // extra exact
		"sub.example.org":         false, // extra exact — subdomain excluded
		"evil.com":                false,
	}
	for host, want := range cases {
		if got := s.IncludesHost(host); got != want {
			t.Errorf("IncludesHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestWithExtraRootsRejectsInvalid(t *testing.T) {
	base, _ := Parse("example.com")
	if _, err := base.WithExtraRoots([]string{"http://bad"}); err == nil {
		t.Error("expected error for invalid asset expression")
	}
}
