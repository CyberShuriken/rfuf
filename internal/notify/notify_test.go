package notify

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/CyberShuriken/rfuf/internal/digest"
)

func sampleDigest() digest.Digest {
	return digest.Digest{
		Domain:        "example.com",
		TotalFindings: 2,
		NewSubdomains: []string{"beta.example.com", "api.example.com"},
		NewJSAssets:   []string{"https://beta.example.com/app.js"},
		Findings: []digest.Category{
			{Name: "exposed_credentials", Severity: "CRITICAL", Count: 1},
			{Name: "cors", Severity: "MEDIUM", Count: 1},
		},
	}
}

// capture spins a local server that records the one request it receives.
func capture(t *testing.T) (*httptest.Server, *string, *string) {
	t.Helper()
	var body, ctype string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		body = string(data)
		ctype = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, &body, &ctype
}

func TestSlackPayloadIsTextField(t *testing.T) {
	srv, body, ctype := capture(t)
	if err := Send(Config{Webhook: srv.URL, Type: "slack"}, sampleDigest()); err != nil {
		t.Fatal(err)
	}
	if *ctype != "application/json" {
		t.Fatalf("content-type=%q", *ctype)
	}
	var payload map[string]string
	if err := json.Unmarshal([]byte(*body), &payload); err != nil {
		t.Fatalf("payload not JSON: %v (%s)", err, *body)
	}
	if !strings.Contains(payload["text"], "beta.example.com") {
		t.Fatalf("slack text missing new subdomain: %q", payload["text"])
	}
	if _, ok := payload["content"]; ok {
		t.Fatal("slack payload should not have a discord content field")
	}
}

func TestDiscordPayloadIsContentField(t *testing.T) {
	srv, body, _ := capture(t)
	if err := Send(Config{Webhook: srv.URL, Type: "discord"}, sampleDigest()); err != nil {
		t.Fatal(err)
	}
	var payload map[string]string
	if err := json.Unmarshal([]byte(*body), &payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload["content"], "example.com") {
		t.Fatalf("discord content missing domain: %q", payload["content"])
	}
}

func TestGenericPayloadIsFullDigest(t *testing.T) {
	srv, body, _ := capture(t)
	if err := Send(Config{Webhook: srv.URL, Type: "generic"}, sampleDigest()); err != nil {
		t.Fatal(err)
	}
	var round digest.Digest
	if err := json.Unmarshal([]byte(*body), &round); err != nil {
		t.Fatalf("generic payload should be the digest struct: %v", err)
	}
	if round.Domain != "example.com" || round.TotalFindings != 2 {
		t.Fatalf("generic payload wrong: %+v", round)
	}
}

func TestDetectTypeFromURL(t *testing.T) {
	cases := map[string]string{
		"https://hooks.slack.com/services/T/B/x":   "slack",
		"https://discord.com/api/webhooks/123/abc": "discord",
		"https://example.com/my/webhook":           "generic",
	}
	for url, want := range cases {
		if got := detectType(Config{Webhook: url}); got != want {
			t.Errorf("detectType(%q)=%q want %q", url, got, want)
		}
	}
}

func TestMaybeSkipsWhenNoChangeInChangeMode(t *testing.T) {
	srv, body, _ := capture(t)
	d := digest.Digest{Domain: "q.com", TotalFindings: 5} // findings but no new surface
	if err := Maybe(Config{Webhook: srv.URL, On: "change"}, d); err != nil {
		t.Fatal(err)
	}
	if *body != "" {
		t.Fatalf("change mode should not send when nothing is new, sent: %q", *body)
	}
}

func TestMaybeSendsOnChangeWhenNewSurface(t *testing.T) {
	srv, body, _ := capture(t)
	d := digest.Digest{Domain: "q.com", NewSubdomains: []string{"new.q.com"}}
	if err := Maybe(Config{Webhook: srv.URL, On: "change"}, d); err != nil {
		t.Fatal(err)
	}
	if *body == "" {
		t.Fatal("change mode must send when a new subdomain appears")
	}
}

func TestMaybeAlwaysSends(t *testing.T) {
	srv, body, _ := capture(t)
	d := digest.Digest{Domain: "q.com"} // nothing new
	if err := Maybe(Config{Webhook: srv.URL, On: "always"}, d); err != nil {
		t.Fatal(err)
	}
	if *body == "" {
		t.Fatal("always mode must send even with no changes")
	}
}

func TestMaybeNoWebhookIsNoop(t *testing.T) {
	if err := Maybe(Config{Webhook: ""}, sampleDigest()); err != nil {
		t.Fatalf("empty webhook should be a silent no-op: %v", err)
	}
}
