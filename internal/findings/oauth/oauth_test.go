package oauth

import (
	"net/url"
	"testing"
)

func TestBypassesFor(t *testing.T) {
	u, err := url.Parse("https://app.example.com/callback")
	if err != nil {
		t.Fatal(err)
	}
	bs := bypassesFor(u)
	if len(bs) != 5 {
		t.Fatalf("got %d bypasses, want 5", len(bs))
	}
	seen := map[string]bool{}
	for _, b := range bs {
		if seen[b.name] {
			t.Errorf("duplicate bypass %q", b.name)
		}
		seen[b.name] = true
		if b.payload == "" {
			t.Errorf("%s has empty payload", b.name)
		}
		if b.curl("https://x/oauth/authorize", "https://app/cb", b.payload) == "" {
			t.Errorf("%s produced empty curl", b.name)
		}
	}
}
