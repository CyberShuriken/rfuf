// Package secheaders implements per-host security header analysis.
//
// For each alive host, the module issues a GET and inspects the
// response headers for the security-relevant ones. Missing or weak
// values are reported in secheaders_findings.txt as one row per
// (host, header, finding) tuple, severity-grouped.
//
// What's checked:
//
//   - Content-Security-Policy    missing = reportable (XSS-class)
//                                unsafe-inline = reportable (XSS bypass)
//                                unsafe-eval = reportable (XSS bypass)
//                                no-https/None over HTTP = reportable
//   - Strict-Transport-Security  missing on HTTPS host = reportable
//                                max-age < 15552000 (180 days) = warn
//                                includeSubDomains missing = info
//   - X-Frame-Options            missing AND no CSP frame-ancestors = reportable
//                                DENY/SAMEORIGIN missing = reportable
//   - Referrer-Policy            missing = reportable (info)
//                                unsafe-url / no-referrer-when-downgrade = warn
//   - Permissions-Policy         missing = info
//   - X-Content-Type-Options     missing nosniff = reportable
//   - Cross-Origin-*             COOP/COEP/CORP missing on hosts that
//                                serve user data = reportable (medium)
//
// Output: secheaders_findings.txt with tab-separated
//
//	severity\thost\theader\tdetail\tseverity
//
// Each row lists the *finding*, not the header. A single host can
// produce multiple rows (one per missing/misconfigured header).
package secheaders

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/CyberShuriken/rfuf/internal/findings/internal/iohelp"
)

// Run is the entry point. workDir is the rfuf work dir; the function
// reads alive.txt and writes secheaders_findings.txt.
func Run(workDir string) error {
	hosts, err := iohelp.ReadLines(workDir + "/alive.txt")
	if err != nil {
		return fmt.Errorf("read alive.txt: %w", err)
	}
	if len(hosts) == 0 {
		return iohelp.WriteLines(workDir+"/secheaders_findings.txt", nil)
	}
	const cap = 250
	if len(hosts) > cap {
		hosts = hosts[:cap]
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	rows := probeAll(ctx, hosts)
	lines := make([]string, len(rows))
	for i, r := range rows {
		lines[i] = r.line()
	}
	return iohelp.WriteLines(workDir+"/secheaders_findings.txt", lines)
}

type row struct {
	host     string
	header   string
	detail   string
	severity string
}

func (r row) line() string {
	return strings.Join([]string{r.host, r.header, r.severity, r.detail}, "\t")
}

func probeAll(ctx context.Context, hosts []string) []row {
	sem := make(chan struct{}, 25)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var out []row

	tr := &http.Transport{MaxIdleConns: 100, MaxIdleConnsPerHost: 5}
	client := &http.Client{
		Transport: tr,
		Timeout:   8 * time.Second,
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
				out = append(out, rs...)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return out
}

func probeHost(ctx context.Context, client *http.Client, host string) []row {
	req, err := http.NewRequestWithContext(ctx, "GET", host, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "rfuf-secheaders/1.0")
	iohelp.ApplyAuth(req)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	// Drain a tiny bit of body so the connection can be reused.
	buf := make([]byte, 1024)
	_, _ = resp.Body.Read(buf)

	var out []row
	h := resp.Header

	// === Content-Security-Policy ===
	csp := h.Get("Content-Security-Policy")
	if csp == "" {
		out = append(out, row{
			host: host, header: "Content-Security-Policy",
			detail: "MISSING — XSS-class impact", severity: "HIGH",
		})
	} else {
		if strings.Contains(csp, "unsafe-inline") {
			out = append(out, row{
				host: host, header: "Content-Security-Policy",
				detail: "unsafe-inline present — bypasses XSS protections", severity: "HIGH",
			})
		}
		if strings.Contains(csp, "unsafe-eval") {
			out = append(out, row{
				host: host, header: "Content-Security-Policy",
				detail: "unsafe-eval present — bypasses JSONP/code injection protection", severity: "MEDIUM",
			})
		}
		if strings.Contains(csp, "*") && strings.Contains(csp, "script-src") {
			out = append(out, row{
				host: host, header: "Content-Security-Policy",
				detail: "wildcard in script-src — loads scripts from any origin", severity: "HIGH",
			})
		}
		if !strings.Contains(csp, "frame-ancestors") {
			out = append(out, row{
				host: host, header: "Content-Security-Policy",
				detail: "no frame-ancestors directive — relies on X-Frame-Options alone", severity: "LOW",
			})
		}
	}

	// === Strict-Transport-Security ===
	if strings.HasPrefix(host, "https://") {
		hsts := h.Get("Strict-Transport-Security")
		if hsts == "" {
			out = append(out, row{
				host: host, header: "Strict-Transport-Security",
				detail: "MISSING on HTTPS host — MITM-class downgrade attack", severity: "HIGH",
			})
		} else {
			// Parse max-age. Conservative: < 180 days = warn.
			maxAge := extractMaxAge(hsts)
			if maxAge < 15552000 {
				out = append(out, row{
					host: host, header: "Strict-Transport-Security",
					detail: fmt.Sprintf("max-age=%d (<180d)", maxAge), severity: "MEDIUM",
				})
			}
			if !strings.Contains(hsts, "includeSubDomains") {
				out = append(out, row{
					host: host, header: "Strict-Transport-Security",
					detail: "missing includeSubDomains — subdomain cookie theft possible", severity: "LOW",
				})
			}
		}
	}

	// === X-Frame-Options ===
	xfo := h.Get("X-Frame-Options")
	hasCSPAncestors := strings.Contains(csp, "frame-ancestors")
	if xfo == "" && !hasCSPAncestors {
		out = append(out, row{
			host: host, header: "X-Frame-Options",
			detail: "MISSING — clickjacking via iframe injection", severity: "MEDIUM",
		})
	}
	if xfo != "" {
		upper := strings.ToUpper(xfo)
		if upper != "DENY" && upper != "SAMEORIGIN" {
			out = append(out, row{
				host: host, header: "X-Frame-Options",
				detail: fmt.Sprintf("unusual value %q — does not DENY/SAMEORIGIN", xfo), severity: "LOW",
			})
		}
	}

	// === X-Content-Type-Options ===
	if !strings.EqualFold(h.Get("X-Content-Type-Options"), "nosniff") {
		out = append(out, row{
			host: host, header: "X-Content-Type-Options",
			detail: "missing nosniff — MIME-sniff attacks possible", severity: "MEDIUM",
		})
	}

	// === Referrer-Policy ===
	rp := h.Get("Referrer-Policy")
	if rp == "" {
		out = append(out, row{
			host: host, header: "Referrer-Policy",
			detail: "MISSING — defaults to no-referrer-when-downgrade which leaks URLs over HTTP", severity: "LOW",
		})
	} else if strings.EqualFold(rp, "unsafe-url") || strings.EqualFold(rp, "no-referrer-when-downgrade") {
		out = append(out, row{
			host: host, header: "Referrer-Policy",
			detail: fmt.Sprintf("weak policy %q — leaks full URL on cross-origin navigation", rp), severity: "LOW",
		})
	}

	// === Permissions-Policy ===
	if h.Get("Permissions-Policy") == "" {
		out = append(out, row{
			host: host, header: "Permissions-Policy",
			detail: "MISSING — iframes can claim camera/mic/geolocation by default", severity: "INFO",
		})
	}

	// === Cross-Origin-Opener-Policy / Embedder-Policy / Resource-Policy ===
	if h.Get("Cross-Origin-Opener-Policy") == "" {
		out = append(out, row{
			host: host, header: "Cross-Origin-Opener-Policy",
			detail: "MISSING — cross-window attacks possible", severity: "INFO",
		})
	}
	if h.Get("Cross-Origin-Embedder-Policy") == "" {
		out = append(out, row{
			host: host, header: "Cross-Origin-Embedder-Policy",
			detail: "MISSING — document isolation disabled", severity: "INFO",
		})
	}
	if h.Get("Cross-Origin-Resource-Policy") == "" {
		out = append(out, row{
			host: host, header: "Cross-Origin-Resource-Policy",
			detail: "MISSING — Spectre-class cross-origin reads possible", severity: "INFO",
		})
	}

	// === Server / X-Powered-By leakage ===
	if xp := h.Get("X-Powered-By"); xp != "" {
		out = append(out, row{
			host: host, header: "X-Powered-By",
			detail: fmt.Sprintf("discloses version: %q", xp), severity: "INFO",
		})
	}

	return out
}

// extractMaxAge parses `max-age=<seconds>` from an HSTS header. We
// don't try to handle every malformed input — 0 is returned on parse
// failure so the calling check sees a weak policy.
func extractMaxAge(hsts string) int {
	upper := strings.ToUpper(hsts)
	i := strings.Index(upper, "MAX-AGE=")
	if i < 0 {
		return 0
	}
	rest := hsts[i+len("MAX-AGE="):]
	j := 0
	for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
		j++
	}
	if j == 0 {
		return 0
	}
	n := 0
	for k := 0; k < j; k++ {
		n = n*10 + int(rest[k]-'0')
	}
	return n
}