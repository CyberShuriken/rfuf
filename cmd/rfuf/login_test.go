package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPerformLoginCapturesSessionCookie(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" && r.Method == "POST" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc123"})
			w.WriteHeader(200)
			w.Write([]byte("welcome back"))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	cookie, err := performLogin(srv.URL+"/login", "email=u@x.com&password=p", "application/x-www-form-urlencoded", "welcome")
	if err != nil {
		t.Fatalf("performLogin: %v", err)
	}
	if !strings.Contains(cookie, "session=abc123") {
		t.Errorf("captured cookie = %q, want it to contain session=abc123", cookie)
	}
}

func TestPerformLoginMarkerMismatchFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "x"})
		w.Write([]byte("invalid credentials"))
	}))
	defer srv.Close()
	if _, err := performLogin(srv.URL, "x=y", "application/x-www-form-urlencoded", "welcome"); err == nil {
		t.Error("expected failure when success marker is absent")
	}
}

func TestPerformLoginNoCookieFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	if _, err := performLogin(srv.URL, "x=y", "application/x-www-form-urlencoded", ""); err == nil {
		t.Error("expected failure when login sets no cookie")
	}
}
