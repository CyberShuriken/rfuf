package jsassets

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunCollectsOnlyScopedAuthenticatedAssets(t *testing.T) {
	var server *httptest.Server
	seenAuth := false
	blockedRequests, evilRequests := 0, 0
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/blocked.js" {
			blockedRequests++
			http.NotFound(w, r)
			return
		}
		if r.Host == "evil.invalid" {
			evilRequests++
			http.NotFound(w, r)
			return
		}
		if r.Host == "fixture.test:"+strings.Split(server.Listener.Addr().String(), ":")[1] && r.URL.Path == "/nested/index.html" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<script src="../assets/app.js"></script><link rel="manifest" href="/manifest.json"><script type="application/json">{"route":"/api/inline"}</script><script src="https://evil.invalid/leak.js"></script><script src="/blocked.js"></script>`))
			return
		}
		if r.URL.Path == "/broken" {
			http.Error(w, "fixture failure", http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path == "/assets/app.js" {
			seenAuth = r.Header.Get("Cookie") == "sid=fixture"
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(`const route="/api/private"; const manifest="/manifest-child.json";`))
			return
		}
		if r.URL.Path == "/manifest.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"routes":{"admin":"/api/v1/admin"},"assets":["/manifest-child.json"]}`))
			return
		}
		if r.URL.Path == "/manifest-child.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"asset":"/child.js"}`))
			return
		}
		if r.URL.Path == "/child.js" {
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(`const endpoint="/api/child";`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	port := strings.Split(server.Listener.Addr().String(), ":")[1]
	oldClient := newClient
	newClient = func() *http.Client {
		return &http.Client{Transport: &http.Transport{DialContext: fixtureDialer(server.Listener.Addr().String())}}
	}
	t.Cleanup(func() { newClient = oldClient })
	t.Setenv("RFUF_AUTH_COOKIE", "sid=fixture")
	t.Setenv("RFUF_EXCLUDE_URL_REGEX", `/blocked\.js`)
	work := t.TempDir()
	if err := os.WriteFile(filepath.Join(work, "scope.json"), []byte(`{"input":"*.fixture.test","root_domain":"fixture.test","mode":"wildcard"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "alive.txt"), []byte("http://fixture.test:"+port+"/nested/index.html\nhttp://www.fixture.test:"+port+"/broken\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Run(work); err != nil {
		t.Fatal(err)
	}
	if !seenAuth {
		t.Fatal("asset request did not include configured cookie")
	}
	if blockedRequests != 0 || evilRequests != 0 {
		t.Fatalf("out-of-scope or excluded request sent: blocked=%d evil=%d", blockedRequests, evilRequests)
	}
	assets, err := os.ReadFile(filepath.Join(work, "js_assets.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(assets), "/assets/app.js") || !strings.Contains(string(assets), "/manifest-child.json") {
		t.Fatalf("expected recursive assets, got %s", assets)
	}
	for _, name := range []string{"js_asset_metadata.jsonl", "js_asset_errors.jsonl", "js_asset_errors.txt", "js_endpoint_provenance.jsonl", "js_endpoints.txt", "jsmap_status.txt"} {
		if _, err := os.Stat(filepath.Join(work, name)); err != nil {
			t.Errorf("missing %s: %v", name, err)
		}
	}
	meta, err := os.ReadFile(filepath.Join(work, "js_asset_metadata.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var foundMetadata bool
	for _, line := range strings.Split(strings.TrimSpace(string(meta)), "\n") {
		var rec assetMetadata
		if json.Unmarshal([]byte(line), &rec) == nil && strings.HasSuffix(rec.URL, "/assets/app.js") {
			foundMetadata = rec.Status == http.StatusOK && rec.ContentType != "" && rec.Bytes > 0 && rec.SHA256 != ""
		}
	}
	if !foundMetadata {
		t.Fatalf("successful asset metadata lacks status/content type/size/hash: %s", meta)
	}
	errors, err := os.ReadFile(filepath.Join(work, "js_asset_errors.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(errors), "http_status_503") || !strings.Contains(string(errors), "out_of_scope_or_excluded") {
		t.Fatalf("expected sanitized fetch and scope errors, got %s", errors)
	}
	endpoints, err := os.ReadFile(filepath.Join(work, "js_endpoints.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(endpoints), "/api/inline") || !strings.Contains(string(endpoints), "/api/private") || strings.Contains(string(endpoints), "evil.invalid") {
		t.Fatalf("unexpected endpoint list: %s", endpoints)
	}
}
