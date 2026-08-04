// Package takeover implements F6: signup / email-verification takeover
// fingerprinting.
//
// Signup-takeover bugs are among the highest-paying findings on
// HackerOne. The pattern: app sends an email-verification link, the
// link's token is either (a) guessable / sequential / signed-with-
// public-info, or (b) re-usable for *any* email address — meaning the
// attacker can take over any account whose verification email they
// can predict or intercept.
//
// What the module does (passive only, no auth attempt):
//
//   1. Probes each alive host for common signup endpoints.
//   2. For endpoints that respond, records:
//      - the response status (201 = signup accepted, 200/302 = form)
//      - any token-shaped strings in the response body
//      - any email-verification URL patterns
//   3. Cross-references against the page's email-template signals
//      (search for "verify", "confirm", "activate", "click here",
//      "?token=", "?code=", "?key=") to find the URL pattern.
//   4. Records each (host, signup_path, verify_url_pattern) tuple in
//      signup_takeover_findings.txt with a "MANUAL_RETEST_REQUIRED"
//      tag — the hunter signs up, intercepts the verification email
//      from a Mailtrap inbox, and confirms whether the token is
//      predictable or reusable.
//
// We deliberately do NOT actually create accounts on the target. The
// data we want is the *response shape* — what does signup look like
// from the outside, what verification URL pattern does the page
// reference, is the signup response a JSON Web Token (which would be
// reportable on its own).
package takeover

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/CyberShuriken/rfuf/internal/findings/internal/iohelp"
)

// signupPaths are the well-known registration endpoints. The list
// covers WordPress (`/wp-login.php?action=register`), Laravel
// (`/register`), Discourse (`/signup`), Django-allauth
// (`/accounts/signup/`), Rails Devise, generic API patterns, and the
// common OIDC dynamic-client-registration path.
var signupPaths = []string{
	"/signup",
	"/sign-up",
	"/sign_up",
	"/register",
	"/registration",
	"/users/sign_up",
	"/accounts/signup/",
	"/api/users",
	"/api/v1/users",
	"/api/v2/users",
	"/api/v1/auth/register",
	"/api/v2/auth/register",
	"/api/v1/accounts",
	"/api/auth/register",
	"/wp-login.php?action=register",
	"/auth/register",
	"/auth/signup",
	"/join",
	"/create-account",
	"/create_account",
	"/new-user",
	"/new_user",
}

// emailConfirmSignals are the keywords that, when found in a page
// body, suggest the app emails a verification link on signup.
var emailConfirmSignals = []string{
	"verify your email",
	"confirm your email",
	"click the link",
	"activate your account",
	"verification link",
	"?token=",
	"?code=",
	"?key=",
	"?activation=",
	"confirm-email",
	"email-verification",
	"email_verification",
}

// tokenPattern matches JWTs, base64-looking strings of 20+ chars, and
// hex tokens. We don't try to *parse* them — we just want to know
// "this signup response carries a token-shaped value," which is itself
// a strong takeover signal.
var tokenPattern = regexp.MustCompile(`(eyJ[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+\.[A-Za-z0-9_.+/=-]+|[A-Fa-f0-9]{32,}|[A-Za-z0-9_-]{32,}\.[A-Za-z0-9_-]{32,}\.[A-Za-z0-9_-]{32,})`)

// Run is the entry point. workDir is the rfuf work dir.
func Run(workDir string) error {
	hosts, err := iohelp.ReadLines(workDir + "/alive.txt")
	if err != nil {
		return fmt.Errorf("read alive.txt: %w", err)
	}
	if len(hosts) == 0 {
		return iohelp.WriteLines(workDir+"/signup_takeover_findings.txt", nil)
	}
	const cap = 200
	if len(hosts) > cap {
		hosts = hosts[:cap]
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	rows := probeAll(ctx, hosts)
	return iohelp.WriteLines(workDir+"/signup_takeover_findings.txt", rows)
}

type row struct {
	host       string
	path       string
	status     int
	hasToken   bool
	hasConfirm bool
	urlPattern string
	severity   string
}

func (r row) line() string {
	tok := "no"
	if r.hasToken {
		tok = "yes"
	}
	conf := "no"
	if r.hasConfirm {
		conf = "yes"
	}
	return strings.Join([]string{
		r.host,
		r.path,
		intToStr(r.status),
		tok,
		conf,
		r.urlPattern,
		r.severity,
		"MANUAL_RETEST_REQUIRED",
	}, "\t")
}

func intToStr(n int) string {
	if n == 0 {
		return "-"
	}
	return itoa(n)
}

// itoa is a local int→string to avoid pulling in fmt for one call.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func probeAll(ctx context.Context, hosts []string) []string {
	sem := make(chan struct{}, 20)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var rows []string

	tr := &http.Transport{MaxIdleConns: 100, MaxIdleConnsPerHost: 5}
	client := &http.Client{
		Transport: tr,
		Timeout:   6 * time.Second,
		// We want raw responses — most signup pages are 200 (form) or
		// 405 (POST-only endpoint), and either tells us the path
		// exists.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, h := range hosts {
		h := h
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			rs := probeHost(ctx, client, h)
			if len(rs) > 0 {
				mu.Lock()
				rows = append(rows, rs...)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return rows
}

func probeHost(ctx context.Context, client *http.Client, host string) []string {
	var rows []string
	for _, p := range signupPaths {
		// GET first to capture form-level signals. A 200 with email
		// confirm signals is a strong indicator the app uses email
		// verification on signup.
		req, err := http.NewRequestWithContext(ctx, "GET", host+p, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "rfuf-takeover/1.0")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()
		// 404 means the path doesn't exist. 405 means POST-only — also
		// a positive signal (signup exists, just won't render via GET).
		if resp.StatusCode == 404 {
			continue
		}

		bodyStr := string(body)
		hasConfirm := false
		lower := strings.ToLower(bodyStr)
		for _, s := range emailConfirmSignals {
			if strings.Contains(lower, s) {
				hasConfirm = true
				break
			}
		}
		hasToken := tokenPattern.MatchString(bodyStr)

		severity := "LOW"
		if hasToken {
			// Signup endpoint returns a token in the response → the
			// attacker doesn't even need to confirm the email. CRITICAL.
			severity = "CRITICAL"
		} else if hasConfirm {
			// Email verification flow → manual retest to see if
			// the token is predictable.
			severity = "HIGH"
		}

		// Best-effort URL pattern extraction. We look for
		// /verify?... or /confirm?... or /activate?... in the page
		// body, plus any absolute URL containing "?token=" or
		// "?code=". We don't try to be exhaustive — the hunter
		// reads this and checks the live email.
		urlPattern := extractURLPattern(bodyStr)

		rows = append(rows, row{
			host:       host,
			path:       p,
			status:     resp.StatusCode,
			hasToken:   hasToken,
			hasConfirm: hasConfirm,
			urlPattern: urlPattern,
			severity:   severity,
		}.line())
	}
	return rows
}

func extractURLPattern(body string) string {
	// Find a quoted URL with one of the known verify params. We
	// limit to the first match — patterns are usually consistent
	// across the app.
	for _, marker := range []string{`"/verify`, `"/confirm`, `"/activate`, `verify?`, `confirm?`, `activate?`} {
		if i := strings.Index(body, marker); i >= 0 {
			// Capture until the closing quote or >.
			end := i + len(marker)
			for end < len(body) && end-i < 200 {
				c := body[end]
				if c == '"' || c == '>' || c == ' ' {
					return body[i:end]
				}
				end++
			}
		}
	}
	// Pattern-2: any absolute URL with ?token= / ?code=.
	for _, q := range []string{"?token=", "?code=", "?key="} {
		if i := strings.Index(body, q); i >= 0 {
			start := i
			for start > 0 && body[start] != '"' && body[start] != '\'' && body[start] != '>' {
				start--
			}
			start++ // step over the quote
			return body[start : i+len(q)] + "..."
		}
	}
	return ""
}
