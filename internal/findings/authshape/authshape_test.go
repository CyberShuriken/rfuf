package authshape

import "testing"

func TestIsSessionCookie(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"sessionid", true},
		{"PHPSESSID", true},
		{"__Host-auth", true},
		{"__Secure-token", true},
		{"JSESSIONID", true},
		{"_ga", false},
		{"_gid", false},
		{"cf_clearance", false}, // Cloudflare, not auth
		{"ajs_anonymous_id", false},
		{"_hjSession_12345", false},
	}
	for _, c := range cases {
		if got := isSessionCookie(c.in); got != c.want {
			t.Errorf("isSessionCookie(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestLooksLikeJWT(t *testing.T) {
	// Real JWT: header.payload.signature
	// header = {"alg":"HS256","typ":"JWT"} → base64url
	hdr := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	payload := "eyJzdWIiOiIxMjM0NSJ9"
	sig := "abc"
	tok := hdr + "." + payload + "." + sig
	if !looksLikeJWT(tok) {
		t.Errorf("looksLikeJWT(%q) = false, want true", tok)
	}
	if looksLikeJWT("not-a-jwt") {
		t.Errorf("looksLikeJWT rejected non-JWT")
	}
	if looksLikeJWT("only.two") {
		t.Errorf("looksLikeJWT accepted 2-segment input")
	}
}

func TestCheckJWTAlgNone(t *testing.T) {
	// alg:none header
	hdr := `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0` // {"alg":"none","typ":"JWT"}
	payload := `eyJzdWIiOiIxIn0`                   // {"sub":"1"}
	sig := ``
	tok := hdr + "." + payload + "." + sig
	fs := checkJWT("https://example.com", tok)
	if len(fs) == 0 || fs[0].Category != "jwt-alg-none" {
		t.Fatalf("expected jwt-alg-none, got %+v", fs)
	}
}

func TestCheckJWTNoExp(t *testing.T) {
	hdr := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9`
	payload := `eyJzdWIiOiIxIn0` // no exp
	sig := `abc`
	tok := hdr + "." + payload + "." + sig
	fs := checkJWT("https://example.com", tok)
	if len(fs) == 0 || fs[0].Category != "jwt-no-exp" {
		t.Fatalf("expected jwt-no-exp, got %+v", fs)
	}
}
