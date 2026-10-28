package specparser

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestRunEmitsPathAndParamURLs(t *testing.T) {
	work := t.TempDir()
	specs := filepath.Join(work, "api_specs")
	if err := os.MkdirAll(specs, 0755); err != nil {
		t.Fatal(err)
	}

	// OpenAPI 3-style doc: one path with a query param, one templated path.
	doc := `{
	  "openapi": "3.0.0",
	  "paths": {
	    "/api/search": {
	      "get": {"parameters": [{"name": "q", "in": "query"}, {"name": "page", "in": "query"}]}
	    },
	    "/api/users/{id}": {
	      "parameters": [{"name": "fields", "in": "query"}],
	      "get": {}
	    },
	    "/health": {"get": {}}
	  }
	}`
	// Lossy filename (dots/slashes collapsed) + a .src sidecar with the real URL.
	fn := filepath.Join(specs, "api_example_com_openapi.json")
	if err := os.WriteFile(fn, []byte(doc), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fn+".src", []byte("https://api.example.com/openapi.json"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := Run(work); err != nil {
		t.Fatalf("Run: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(work, "openapi_paths.txt"))
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSpace(string(data)), "\n")
	sort.Strings(got)

	// Host reconstructed from .src (not the lossy filename); templated {id}
	// substituted; query params synthesized as name=FUZZ.
	mustContain(t, got, "https://api.example.com/api/search")
	mustContain(t, got, "https://api.example.com/health")
	mustContain(t, got, "https://api.example.com/api/users/1")
	// param URL present (order of q/page is map-dependent, so check membership)
	if !hasParamURL(got, "https://api.example.com/api/search?", []string{"q=FUZZ", "page=FUZZ"}) {
		t.Errorf("missing synthesized search param URL in %v", got)
	}
	if !hasParamURL(got, "https://api.example.com/api/users/1?", []string{"fields=FUZZ"}) {
		t.Errorf("missing synthesized users param URL in %v", got)
	}
}

func mustContain(t *testing.T, hay []string, needle string) {
	t.Helper()
	for _, h := range hay {
		if h == needle {
			return
		}
	}
	t.Errorf("expected %q in %v", needle, hay)
}

func hasParamURL(hay []string, prefix string, params []string) bool {
	for _, h := range hay {
		if !strings.HasPrefix(h, prefix) {
			continue
		}
		ok := true
		for _, p := range params {
			if !strings.Contains(h, p) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
