# RFUF Bug-Finding Expansion — Tasklist

Goal: turn `rfuf` from "scanner that returns empty" into a high-signal bug
hunting tool that surfaces manual-retest candidates across ~25 bug classes
the existing pipeline misses. Scope: **wire up the 10 unwired finders, add
new finders, add custom nuclei templates, with RFUF_AUTH_* support and
WAF-bypass chaining.**

Each task is a discrete commit with a build-check at the end.

---

## Phase 1 — Wire up the 10 already-written finders

These modules are written but not invoked by any pipeline stage. They
read existing artifacts (`alive.txt`, `all_urls.txt`, `js_bundles/`,
`tech_fingerprint.txt`, `live_subs.txt`) and write their own findings
files that `summary.go` doesn't currently ingest.

| Task | Description | Status |
|------|-------------|--------|
| 1.1 | Wire `reflection` finder as `reflection_run` step after `url_filter_alive` | ✅ |
| 1.2 | Wire `paramshape` finder as `paramshape_run` step after `httpx_probe` | ✅ |
| 1.3 | Wire `authshape` finder as `authshape_run` step after `httpx_probe` | ✅ |
| 1.4 | Wire `takeover` (signup/email-verify) finder as `signup_takeover_run` | ✅ |
| 1.5 | Wire `idor` (surface map) finder as `idor_surface_run` after `merge_all_urls` | ✅ |
| 1.6 | Wire `oauth` (redirect_uri bypass) finder as `oauth_audit_run` | ✅ |
| 1.7 | Wire `race` finder as `race_scan` step after `manual_review_queue` | ✅ |
| 1.8 | Wire `buckets` finder as `bucket_guess_run` step after `tech_fingerprint` | ✅ |
| 1.9 | Wire `takeoversvc` (Vercel/Netlify/Fly/AzSWA) finder as `takeover_v2_run` | ✅ |
| 1.10 | Wire `jsmine` (deep JS mining) finder as `js_mine_run` after `jsmap_scrape` | ✅ |
| 1.11 | Update `summary.go` to ingest the 10 new findings files + add severity-grouped sections | ✅ |
| 1.12 | Add `go run ./internal/findings/<name>` wrappers (filter_testable_ref pattern) | ✅ |

**Build check:** `go build ./cmd/rfuf && go test ./internal/pipeline/...`

---

## Phase 2 — Add 5 new finder modules

These are bug classes the existing pipeline does not cover at all:

| Task | Description | Status |
|------|-------------|--------|
| 2.1 | `internal/findings/secheaders/` — security headers analysis (CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy). Missing CSP = XSS-class. Weak HSTS = MITM-class. | ✅ |
| 2.2 | `internal/findings/backupscan/` — backup/sensitive-file probing (`/.env`, `/.git/config`, `/backup.zip`, `/db.sqlite3`, `/.DS_Store`, `/.svn/entries`, IDE tempfiles). The single highest-yield bug class on most programs. | ✅ |
| 2.3 | `internal/findings/businesslogic/` — extend the existing `manual_business_logic_review.txt` with auto-detection of currency/price-manipulation, negative-quantity, and integer-overflow params | ✅ |
| 2.4 | `internal/findings/hostheader/` — Host header injection probe (password-reset poisoning, cache poisoning via Host header). Tests the URL with a different Host header and watches for it reflected in body or Location. | ✅ |
| 2.5 | `internal/findings/cors2/` — augment the existing CORS check with credentialed preflight (Access-Control-Request-Method + private network access) — modern browser attack vectors the legacy check misses. | ✅ |

---

## Phase 3 — Custom nuclei templates for missing bug classes

Nuclei's default tags are quiet on real targets. Add a `nuclei-templates-rfuf/`
overlay with high-signal templates:

| Task | Description | Status |
|------|-------------|--------|
| 3.1 | `cves/2024-CVE-grab-bag.yaml` — covers top-5 most-reported 2024-2026 CVEs by impact (Next.js middleware bypass, Fortinet auth-bypass, etc.) | ✅ |
| 3.2 | `exposures/debug-endpoints.yaml` — `/debug`, `/_debug`, `/elmah.axd`, `/trace.axd`, `/server-status`, `/nginx_status`, `/phpinfo.php` | ✅ |
| 3.3 | `exposures/saas-tokens.yaml` — Intercom, Segment, Mixpanel, Datadog tokens in HTML/JS (not just JS bundles) | ✅ |
| 3.4 | `misconfig/cors-credentialed.yaml` — strict credentialed-CORS detector (replaces inline bash check) | ✅ |
| 3.5 | Wire `nuclei -t nuclei-templates-rfuf/` as a final-pass step that runs after all other scans | ✅ |

---

## Phase 4 — Auth + WAF bypass chaining

The user provides auth via `-auth-cookie` / `-auth-bearer` (already wired
in executor.AuthEnv). Modules must thread it through HTTP requests.

WAF bypass: `waf_detect` stage produces `waf_detections.txt`. The
`nuclei_optimized_auth()` and `dalfox` invocation should pick a tamper
profile from a static catalog keyed by detected WAF.

| Task | Description | Status |
|------|-------------|--------|
| 4.1 | Helper `internal/findings/internal/iohelp/auth.go` — `BuildAuthHeaders()` returns `-H "Cookie: ..."` / `-H "Authorization: Bearer ..."` block for Go HTTP clients | ✅ |
| 4.2 | Update existing finders (`reflection`, `paramshape`, `authshape`, `takeover`, `idor`, `oauth`, `race`, `buckets`, `takeoversvc`, `jsmine`, plus new ones) to read `RFUF_AUTH_COOKIE` / `RFUF_AUTH_HEADER` from the process env and apply them on every request | ✅ |
| 4.3 | `internal/findings/internal/wafbypass/` — tamper catalog: per-WAF payload prefix/suffix (Cloudflare, AWS, Imperva, Akamai, Sucuri, F5) for XSS/SQLi/SSRF payloads. Returns the tamper string. | ✅ |
| 4.4 | Wire the WAF catalog into the dalfox/nuclei/sqlmap stage commands so detected WAFs produce tampering flags | ✅ |

---

## Phase 5 — Report integration + finalization

| Task | Description | Status |
|------|-------------|--------|
| 5.1 | Add new `findings.md` sections for the 5 new finder classes (backup scan, host header, secheaders, business-logic, CORS-preflight) with manual-retest hints | ✅ |
| 5.2 | Update SUMMARY.md to surface counts for every new finding bucket | ✅ |
| 5.3 | Update README.md pipeline-stages table with the new stages | ✅ |
| 5.4 | Update ARCHITECTURE.md with the new modules and the AuthEnv/WAF-bypass wiring | ✅ |
| 5.5 | `go build ./cmd/rfuf && go test ./...` — full test pass | ✅ |

---

## Out of scope (intentionally)

- Auth-naive reports only when `RFUF_AUTH_*` is unset (per user decision).
- No auto-registration of test accounts (per user decision).
- macOS / WSL testing (in existing roadmap; not blocked by this work).