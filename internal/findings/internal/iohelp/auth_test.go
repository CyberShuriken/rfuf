package iohelp

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestScopedRequestConstructionAndAuth(t *testing.T) {
	t.Setenv("RFUF_SCOPE_INPUT", "*.fixture.test")
	t.Setenv("RFUF_AUTH_COOKIE", "sid=fixture-secret")
	t.Setenv("RFUF_AUTH_HEADER", "token-secret")
	t.Setenv("RFUF_BUG_BOUNTY_USERNAME", "fixture-program")
	t.Setenv("RFUF_TEST_ACCOUNT_EMAIL", "fixture@example.test")
	t.Setenv("RFUF_EXCLUDE_URL_REGEX", `/private`)

	req, err := NewRequestWithContext(context.Background(), http.MethodGet, "https://api.fixture.test/public", nil)
	if err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("Authorization") != "Bearer token-secret" || req.Header.Get("Cookie") != "sid=fixture-secret" {
		t.Fatalf("auth headers not propagated: %#v", req.Header)
	}
	if req.Header.Get("X-Bug-Bounty") != "fixture-program" || req.Header.Get("X-HackerOne-Research") != "fixture-program" || req.Header.Get("X-Test-Account-Email") != "fixture@example.test" {
		t.Fatalf("program headers not propagated: %#v", req.Header)
	}
	for _, target := range []string{"https://fixture.test.evil.test/public", "https://api.fixture.test/private"} {
		if _, err := NewRequest(http.MethodGet, target, nil); err == nil || strings.Contains(err.Error(), target) {
			t.Fatalf("unsafe target was not rejected with a redacted error (%s): %v", target, err)
		}
	}
}

func TestHardenClientRejectsRedirectOutsideScope(t *testing.T) {
	t.Setenv("RFUF_SCOPE_INPUT", "*.fixture.test")
	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.URL.Hostname() == "start.fixture.test" {
			return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"https://outside.test/"}}, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), Request: req}, nil
	})}
	HardenClient(client)
	req, err := NewRequest(http.MethodGet, "https://start.fixture.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Do(req)
	if err == nil || !strings.Contains(err.Error(), "out_of_scope") {
		t.Fatalf("out-of-scope redirect not blocked: %v", err)
	}
	if calls != 1 {
		t.Fatalf("redirect request escaped the policy transport, calls=%d", calls)
	}
}

func TestHardenClientFailsClosedWithoutScope(t *testing.T) {
	t.Setenv("RFUF_SCOPE_INPUT", "")
	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, nil
	})}
	HardenClient(client)
	_, err := client.Get("https://example.test/")
	if err == nil || calls != 0 {
		t.Fatalf("client without scope did not fail closed: calls=%d err=%v", calls, err)
	}
}
