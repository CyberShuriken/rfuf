# rfuf — Recon Faster U Fool

> One command. Full recon pipeline. Parallel. Resumable. Self-installing.

`rfuf` is a single-binary orchestration layer that chains together the
bug-bounty recon tools you already use — `subfinder`, `dnsx`, `httpx`,
`katana`, `nuclei`, `sqlmap`, `dalfox`, `ffuf`, and more — into a 
**parallelized, dependency-aware** pipeline that is checkpointed and restartable.

It does not reinvent any of those tools. It just runs them in the right
order, against the right files, with the right flags, and remembers where
it left off if anything goes wrong.

---

## Table of Contents

- [Why](#why)
- [Features](#features)
- [How It Works](#how-it-works)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Pipeline Stages](#pipeline-stages)
- [Output Layout](#output-layout)
- [Resume vs. Fresh Run](#resume-vs-fresh-run)
- [Tools Orchestrated](#tools-orchestrated)
- [Project Layout](#project-layout)
- [Roadmap](#roadmap)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## Why

Bug-bounty recon usually means running the same ten tools in the same
order, every time, for every new target — and starting over from zero if
your laptop sleeps, the Wi-Fi drops, or the process gets killed. `rfuf`
encodes that chain as a pipeline, persists progress to disk after every
step, and can resume exactly where it stopped.

## Features

- **Single command, parallel pipeline** — intelligent dependency tracking
  allows multiple tools to run simultaneously (e.g., `subfinder`, `assetfinder`,
  and `amass` run in parallel) while ensuring data integrity.
- **Crash-safe checkpoints** — every completed step is written to
  `checkpoint.json`. Kill the process, restart, pick up where you stopped.
- **Self-installing** — missing tools are detected and installed via
  `go install` or `apt`. GF patterns are cloned if absent.
- **One-command system install** — `rfuf install` places the binary in
  `/opt/rfuf/` and auto-configures your shell.
- **Live Multi-Stage Dashboard** — real-time tracking of all active stages
  with a visual progress bar and live vulnerability stats.
- **Zero configuration** — no API keys, no YAML, no environment file. Pass
  `-d` and go.
- **Per-domain output directory** — clean separation between targets.
- **Explicit scope modes** — bare `example.com` scans only that exact host; explicit `*.example.com` scans the root and proper subdomains. Both use one stable root-domain output directory while preserving the selected mode.
- **OWASP Top 10:2025 coverage report** — maps completed stages and candidate evidence to A01–A10 without claiming that black-box scanning proves every category.
- **Exact manual test plan** — writes candidate-specific identity, control, evidence, and stop-condition guidance for tests that require two accounts, source, deployment, workflow, or logging access.
- **Auto-generated `findings.md`** — severity-grouped report with retest
  hints per vulnerability class and a transparent "what was filtered out"
  appendix. Open this first after a run.
- **Pure Go** — single static binary, no runtime dependencies.

### High-Signal Methodology Modules (NEW)

The default scanner chain (sqlmap, dalfox, nuclei, ffuf) catches the
low-hanging fruit but is **quiet on real targets** because modern apps
use ORMs, CSRF tokens, and CSP headers that block the obvious payloads.
The wired-up Go finder modules (`internal/findings/*`) cover the bug
classes those scanners miss:

| Module | Bug class | Severity | Why the existing tools miss it |
|--------|-----------|----------|--------------------------------|
| `reflection` | Per-URL reflection-site classification | High | dalfox sends payloads blindly; this tells you exactly which site class each param lands in |
| `paramshape` | HTTP Parameter Pollution (HPP) | High | No scanner tests the 5 distinct HPP shapes |
| `authshape` | Cookie / JWT misconfig | High | Nuclei JWT templates catch known patterns; this catches `kid` injection, missing `exp`, etc. |
| `signup` | Email-verification takeover | High | No scanner probes signup flows for token reusability |
| `idor` | IDOR surface map | Medium | Requires 2 test accounts; we build the per-param candidate list |
| `oauth` | redirect_uri bypass | High | Programs ban active auth probing; we emit ready-to-curl candidates |
| `race` | Race conditions (coupon/transfer/vote) | High | The 20-way concurrent probe is the textbook TOCTOU signal |
| `buckets` | Public S3/GCS/Azure | Critical | subzy only checks DNS; we HEAD-test permutations |
| `takeoversvc` | Vercel/Netlify/Fly/AzSWA | High | subzy fingerprints the old services; this catches the 2024-era ones |
| `jsmine` | Deep JS bundle mining | Critical | trufflehog only verifies signatures; this finds POST endpoints, admin paths, mutations |
| `secheaders` | Missing CSP/HSTS/X-Frame | Medium | No scanner reports header gaps |
| `backupscan` | `.env`/`.git`/`db.sql`/`id_rsa` | Critical | The single highest-yield bug class |
| `businesslogic` | Pricing/coupon/balance surface | Medium | Generic scanner payloads miss logic flaws |
| `hostheader` | Host-header injection | High | Password-reset poisoning + cache poison class |
| `cors2` | Credentialed CORS preflight | High | The inline CORS check misses preflight and null-origin |

Plus a `nuclei-templates-rfuf/` overlay with 6 custom templates covering
debug endpoints, SaaS tokens in HTML, JWT alg:none, host-header, and
credentialed CORS preflight.

### Auth + WAF Bypass Chaining (NEW)

- **Auth**: pass `-auth-cookie "session=..."` or `-auth-bearer "..."` and
  every Go finder + every httpx/nuclei stage threads it as the
  Authorization or Cookie header. Unset = unauthenticated scan (legacy).
- **WAF bypass**: `waf_detect` runs first; `buildWafTamperSnippet()`
  reads the output and sets `WAF_SQLMAP_TAMPER` + `WAF_DALFOX_BYPASS`
  env vars; sqlmap and dalfox stages interpolate these as
  `--tamper=$WAF_SQLMAP_TAMPER` and `--bypass=$WAF_DALFOX_BYPASS`.
  Catalog covers Cloudflare, AWS, Imperva, Akamai, F5, Barracuda,
  Sucuri, Fastly, plus a generic fallback.

## How It Works

```
┌──────────────────────────────────────────────────────────────┐
│  rfuf -d target.com                                          │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       ▼
        ┌────────────────────────────┐
        │  1. Resolve paths & tools  │
        └────────────┬───────────────┘
                     ▼
        ┌────────────────────────────┐
        │  2. Load / reset checkpoint│  ◄── crash-safe state
        └────────────┬───────────────┘
                     ▼
   ┌─────────────────────────────────────────────┐
   │  3. Parallel Pipeline Execution              │
   │     (Dependency-aware graph execution)      │
   │                                             │
   │     • Runs multiple tools simultaneously    │
   │     • Thread-safe checkpointing             │
   └─────────────────────┬───────────────────────┘
                         ▼
              ┌──────────────────────┐
              │  4. Generate SUMMARY │
              └──────────────────────┘
```

## Requirements

| Requirement | Version | Notes |
|-------------|---------|-------|
| Go          | 1.22+   | `sudo dnf install -y golang` (Fedora) / `sudo apt install -y golang-go` (Kali/Debian/Ubuntu) |
| Linux       | Fedora 41+ or Kali / Debian / Ubuntu 22.04+ | macOS likely works but is untested |
| `sudo`      | —       | Required for installing `seclists` / `sqlmap` via `apt`/`dnf` |
| Disk        | ~2 GB   | Tool binaries + nuclei templates + SecLists |
| Python 3    | 3.10+   | Required on Fedora for `wafw00f`, `arjun`, `ghauri` (already present on Kali) |

`jq`, `seclists`, and every Go-based tool are auto-installed on first
run if missing. The installer detects your package manager (Fedora →
`dnf`, Kali/Debian/Ubuntu → `apt`) and uses the right install command
for each.

## Installation

The recommended one-time install places the binary at `/opt/rfuf/rfuf`
and wires your shell so `rfuf` works from any directory:

```bash
git clone https://github.com/CyberShuriken/rfuf.git
cd rfuf
make build          # produces ./bin/rfuf
./bin/rfuf install  # builds, copies to /opt/rfuf, patches ~/.zshrc or ~/.bashrc
```

`rfuf install` will:

1. Detect your shell from `$SHELL` and confirm before patching.
2. Create `/opt/rfuf/` (via `sudo` if needed) and copy the binary in.
3. Append `export PATH="/opt/rfuf:$PATH"` to `~/.zshrc` or `~/.bashrc`
   (whichever matches your shell). The append is idempotent — a marker
   comment prevents duplicates on re-runs.

Open a new shell, then verify:

```bash
which rfuf        # → /opt/rfuf/rfuf
rfuf -v           # → rfuf version 2.4.0
```

For full details, troubleshooting, and uninstall instructions see
[INSTALL.md](INSTALL.md).

### Manual install (fallback)

If you would rather wire it up by hand, or cannot use `sudo`:

```bash
make install                                   # → $GOPATH/bin/rfuf
export PATH="$HOME/go/bin:$PATH"               # add to your shell rc

# or:
make build
sudo cp bin/rfuf /usr/local/bin/               # any dir already on $PATH
```

## Usage

```bash
rfuf install                       # one-time system install (places binary in ~/.local/share/rfuf)
rfuf update                        # rebuild from the clone and replace the installed binary
rfuf -d example.com                # exact host only
rfuf -d '*.example.com'             # explicit wildcard: root + subdomains
rfuf -d example.com -resume        # continue a previously interrupted scan (skips installer)
rfuf -d example.com -step-timeout 4h  # allow up to four hours per stage
rfuf -d example.com -skip-install  # like -resume, but on a fresh scan (debug / CI)
rfuf -d example.com -auth-cookie 'session=...' # replay an authorized session cookie
rfuf -d example.com -auth-cookie-file ~/.config/rfuf/session.cookie # read cookie locally
rfuf -d example.com -auth-bearer-file ~/.config/rfuf/token # read bearer token locally
rfuf -d example.com -auth-required -auth-cookie-file ~/.config/rfuf/session.cookie
rfuf -d example.com -bug-bounty-username researcher -test-account-email test@example.com
rfuf -d example.com -exclude-url-regex '(^|/)(contact|support)(/|$)'
rfuf -v                            # print version
rfuf -h                            # show help
```

By default all output is written to:

```
~/Desktop/Bug_Bounty/example.com/
```

Override the working directory or target list is intentionally not
exposed — the tool is opinionated by design.

### Domain scope modes and authorization

`-d example.com` means **exact mode**: RFUF actively probes only `example.com`. `-d '*.example.com'` means **explicit wildcard mode**: RFUF actively probes `example.com` and proper subdomains such as `api.example.com`. A bare domain never expands to subdomains implicitly.

Both modes use the normalized root for the output directory, while `scope.json` records the original input and selected mode. Lookalikes such as `example.com.evil.test` and third-party assets discovered through redirects, scripts, or history are retained as rejected evidence and are not actively probed.

A wildcard is not permission to scan every related asset. Run RFUF only against assets explicitly authorized by the program or asset owner, and review `scope.json`, `in_scope_hosts.txt`, and `out_of_scope_hosts.txt` before relying on the results.

Resume operations must use the same scope mode as the original run. If a scan was started with `example.com`, changing to `*.example.com` requires a fresh run without `-resume`; RFUF rejects a mode mismatch instead of silently expanding the old scan.

### Authenticated testing

RFUF does not create accounts, guess credentials, or automatically submit a
signup form. For an authorized private-surface scan, provide a session that
you created through the target’s normal login flow with `-auth-cookie`,
`-auth-cookie-file`, `-auth-bearer`, or `-auth-bearer-file`. The file forms
contain one cookie value or bearer token and should be readable only by the
operator. Use `-auth-required` when a run must fail rather than silently fall
back to public-only coverage.

Authentication is threaded through HTTP probing, crawling, API discovery,
JavaScript and manifest downloads, nuclei, SQLmap, and Go finder requests.
Secrets are passed through the child environment and argument arrays rather
than interpolated into generated URLs. The scan report records whether auth
was supplied but does not intentionally print the credential value.

### Program-required headers and exclusions

Manual bug-bounty scans can provide program attribution headers with
`-bug-bounty-username` and `-test-account-email`. RFUF propagates these as
`X-Bug-Bounty` and `X-Test-Account-Email` through shell stages and Go finder
requests without storing their values in findings files. Use
`-exclude-url-regex` for program-specific exclusions; the expression is
applied before the canonical HTTP probe and downstream target generation.
This is intended for exclusions such as contact/support forms, sandbox hosts,
or other surfaces listed by the program policy.

### Stage integrity and coverage reports

RFUF now records one lifecycle file per stage under `.rfuf/stages/<stage-id>.json`. Each record includes the stage status, dependencies, exit code, timeout state, input/output counts, and declared artifact state. A zero-finding result can be `completed_empty`; it is distinct from `failed`, `timed_out`, `blocked`, or `skipped`.

The final run writes `.rfuf/coverage_report.json`, `CoverageReport.md`, `evidence.jsonl`, and a coverage section in `SUMMARY.md`. RFUF prints `Pipeline complete` only when every declared stage completed or completed empty. If a required stage fails, times out, is blocked, or is skipped, RFUF preserves partial artifacts but exits with an incomplete-coverage error. This prevents a successful-looking orchestration message from hiding scanner gaps.

### Authentication verification and run limits

When a session is supplied, `-auth-check-url` can make a bounded request to an operator-selected authenticated health-check endpoint. Add `-auth-check-marker` when the response must contain a known marker. RFUF records only boolean verification state and HTTP status in `.rfuf/auth_check.json`; it never stores the marker or credential value. With `-auth-required`, a failed or mismatched health check stops the run before active scanning.

Use `-max-targets` to cap final scoped URL streams and `-max-stage-requests` to set the rate ceiling for scanners that support a rate option. These controls are conservative bounds, not a universal request counter for tools that do not expose a compatible budget interface.

The dashboard shows stage health separately from finding counts and redacts noisy scanner statistics and request metadata from the live panel. Raw child output remains in `.rfuf/rfuf.log` for local troubleshooting.

### OWASP coverage, evidence, and manual validation

The finalization step writes `OWASP_2025_COVERAGE.md`, `candidate_index.jsonl`, and `MANUAL_TEST_PLAN.md`. The coverage report distinguishes `covered`, `partial`, `blocked`, and completed-empty states. A category can remain partial or blocked because some OWASP risks require source code, dependency manifests, deployment configuration, two authorized identities, business context, or security-log access.

`MANUAL_TEST_PLAN.md` turns candidates such as IDOR/BOLA, privileged paths, OAuth, business logic, races, JWT, CORS, and injection into precise, non-destructive tasks. It specifies the required identity or role, expected control, evidence to capture, and stop conditions. RFUF never creates accounts, guesses credentials, bypasses MFA, or treats a scanner lead as a confirmed vulnerability.

### Evidence index and validation state

`evidence.jsonl` contains redacted candidate metadata for high- and medium-impact artifact categories. Each record identifies the category, source artifact, target when safely extractable, severity, confidence, and `validation_state=candidate`. It does not copy secret values, cookies, bearer tokens, or response bodies. Scanner output remains a lead until manually reproduced and impact-confirmed on an authorized test account.

### Enriched target streams

The early host probe writes `alive.txt`, but endpoint scanners no longer stop
there. RFUF merges crawl and historical URLs, OpenAPI/Swagger paths, and
JavaScript/manifest endpoints into `all_urls.txt`, then writes the bounded
`nuclei_targets.txt` stream used by the exposure, misconfiguration, auth, and
GraphQL nuclei passes. The JavaScript collector covers HTML script and link
references, Next.js `/_next/static/` chunks, conventional `/static/js/`
assets, source maps, and common manifest files.

Each pipeline stage has a 30-minute wall-clock limit by default. Tightening
this from the previous 2-hour default means a single hung tool can't pin the
dashboard indefinitely — the step gets killed and the orchestrator continues
with whatever output was produced. Use `-step-timeout <duration>` to raise it
on big targets, or `-step-timeout 0` only when you explicitly want unlimited
stage runtime. Stages with known-bounded runtime (gau, waybackurls) additionally
carry their own per-stage cap (10 minutes); see the stage table below.

### Fedora setup troubleshooting

On Fedora, RFUF passes the terminal’s standard input to `sudo dnf`, so package installation can request the user password normally. The installer checks representative executables rather than treating package names such as `ca-certificates` and `openssl` as PATH commands; this prevents a needless `git` package prompt when Git is already installed.

If RFUF is launched without an interactive terminal and a required Fedora package is missing, it now prints an actionable message instead of waiting for a password that cannot be read. Install the prerequisites manually, then rerun with `-skip-install` only after the required tools are present:

```bash
sudo dnf install -y git ca-certificates openssl gcc make jq sqlmap
test -t 0 && echo "interactive terminal available"
rfuf -d '*.example.com' -skip-install
```

The interactsh callback client is optional. RFUF waits up to 20 seconds by default and continues without OOB callbacks if registration is unavailable. Use `-interactsh-timeout 0` or `-disable-interactsh` when the target, network, or bounty policy does not permit OOB callbacks. Successful interactsh startup now keeps the client alive for the scan instead of cancelling it when startup returns.

If a run reports `step subfinder incomplete (status=failed exit_code=0)`, update RFUF and rerun. The stage-health artifact map now validates `subfinder.txt` and `amass_raw.txt`, the files those commands actually produce; a genuinely empty result is recorded as `completed_empty`, not failed.

### Bounded dependency installation

The installer uses `GOTOOLCHAIN=local` for Go-based dependencies and pins
Nuclei to a Go 1.22-compatible release. It will not silently download a future
Go toolchain during a scan. If a dependency is unavailable, install that tool
explicitly and use `-skip-install` only after the tool verification check
passes; this keeps manual scans from becoming an unbounded setup loop.

### `-resume` implies `-skip-install`

Re-running the full dependency installer on every resume was the source of the
**fanbox.cc hang** (Aug 2026). On a stopped pipeline:

1. `EnsureTools` was triggered, which detected `naabu` (genuinely missing) and
   queued a `go install` for it. Good.
2. But it also queued `sudo dnf install git ...` on Fedora, which silently
   failed because there is no interactive TTY in a non-interactive terminal —
   and the install step ran for minutes before falling through to PATH checks.
3. In parallel, `pipx install wafw00f` and `pipx install ghauri` were attempted,
   triggering Python dependency resolution that takes 5–10 minutes each.

Net effect: every `-resume` wasted ~15 minutes *before any pipeline work resumed*.

As of this release, `-resume` and the explicit `-skip-install` flag both call
the lightweight `VerifyToolsPresent` instead: every required binary is looked
up on `$PATH` and the run aborts with a clear message ("missing naabu, wafw00f,
ghauri — drop -resume to install") if anything is gone. Drop the flag once
to run the installer; subsequent resumes stay fast.

### After rebuilding from source: `rfuf update`

`rfuf -v` prints the binary version at startup and `rfuf update` prints the source directory it is rebuilding. If the version or startup behavior does not change after an update, the shell is executing a different binary; check `command -v rfuf` and `type -a rfuf`.

`RFUF_SOURCE_DIR=/path/to/rfuf rfuf update` can be used when the command is launched outside the clone. Otherwise run `rfuf update` from the repository or one of the standard clone locations.

`rfuf install` places the binary at `~/.local/share/rfuf/rfuf` and wires
the `~/.local/bin/rfuf` symlink. Once installed, the binary is **frozen
on disk** — subsequent `git pull` + `go build` invocations update the
source tree and the `./rfuf` binary in your workdir, but leave the
installed binary untouched. A stale installed binary means the
`-resume` you just kicked off is using the *old* executor / pipeline /
stage list (e.g., the old serial `while read; do ffuf; done` loop and
the old `sqlmap --level=2 --risk=2` flags on Aug 2026 builds).

The fix is one command:

```bash
rfuf update        # rebuilds and replaces ~/.local/share/rfuf/rfuf
```

`update` is `install` without the interactive shell prompt and without
the rc-file patch — strictly the "I just rebuilt from source and want
the new code on PATH" verb. Re-running `rfuf install` does the same
thing but prompts you first.

## Pipeline Stages

`rfuf` runs the following stages in order. Every stage is checkpointed;
re-running with `-resume` skips the ones already completed. Stages
added per the bb-methodology / security-arsenal playbook are marked
**new**.

| # | Stage | Tool(s) | Output |
|---|-------|---------|--------|
| 1 | Subdomain enumeration | `subfinder`, `assetfinder`, `amass` | `subs.txt` |
| 2 | Scope guard (**new**) | Built-in exact-root/subdomain filter | `scope.json`, `in_scope_hosts.txt`, `out_of_scope_hosts.txt`, `scoped_subs.txt` |
| 3 | DNS resolution | `dnsx` | `live_subs.txt` |
| 4 | Subdomain takeover | `subzy` + `nuclei` | `validated_takeovers.txt` |
| 5 | HTTP probing | `httpx` | `alive.txt` |
| 5 | Exposure scanning | `nuclei` (token-spray/exposure/config) | `credentials_found.txt` |
| 6 | Misconfiguration scan | `nuclei` (vulns / exposed panels / misconfig) | `misconfigs.txt` |
| 7 | Auth/JWT scan | `nuclei` (jwt/auth-bypass/default-login) | `auth_results.txt` |
| 8 | GraphQL exposure | `nuclei` (graphql panel templates) | `graphql_exposed.txt` |
| 9 | Crawling | `katana` | `katana_urls.txt` → `clean_katana_urls.txt` |
| 10 | Secret scanning | `trufflehog` + grep | `trufflehog_results.txt`, `potential_secrets.txt` |
| 11 | Historical URL mining | `gau`, `waybackurls` | `all_urls.txt` |
| 12 | URL dedup (**new**) | `uro` | `all_urls.txt` (in place) |
| 13 | 200-only URL filter (**new**) | `httpx -mc 200` | `all_urls_200.txt` |
| 14 | SQLi scan | `gf sqli` → `sqlmap` (level=3, risk=1) | `sqlmap_results/` |
| 15 | SQLi modern scan (**new**) | `ghauri` (BT technique) | `ghauri_results.txt` |
| 16 | XSS scan | `gf xss` → `Gxss` → `dalfox` | `xss_vulnerabilities.txt` |
| 17 | RCE scan | `gf rce` → `nuclei` | `nuclei_rce_rce.txt` |
| 18 | IDOR scan | `gf idor` → `nuclei` | `idor_vulnerabilities.txt` |
| 19 | SSRF scan | `gf ssrf` → `nuclei` | `ssrf_vulnerabilities.txt` |
| 20 | Open redirect scan | `gf redirect` → `nuclei` | `open_redirect_results.txt` |
| 21 | LFI scan | `gf lfi` → `nuclei` | `lfi_results.txt` |
| 22 | CORS reflective-origin check | `curl` via `xargs -P 20` (parallel, top 500 hosts) | `cors_findings.txt` |
| 23 | Directory brute-force | `ffuf` (small wordlist + recursion) | `ffuf_results/`, `ffuf_dirs_raw.txt` |
| 24 | 200-only verify (**new**) | `httpx -mc 200` on ffuf hits | `ffuf_dirs_200.txt` |
| 25 | WAF detection (**new**) | `wafw00f` (capped to 200 hosts) | `waf_detections.txt` |
| 26 | Port scan (**new**) | `naabu` | `naabu_ports.txt` |
| 27 | Hidden params (**new**) | `arjun` (capped to 100 hosts) | `hidden_params.txt` |
| 28 | Manual review queue | `grep` | `manual_business_logic_review.txt` |
| 29 | Reflection finder (**new**) | `go run ./cmd/findings-runner reflection` | `reflection_findings.txt` |
| 30 | Param-shape / HPP (**new**) | `go run ./cmd/findings-runner paramshape` | `paramshape_findings.txt` |
| 31 | Cookie/JWT misconfig (**new**) | `go run ./cmd/findings-runner authshape` | `authshape_findings.txt` |
| 32 | Signup / email-verify takeover (**new**) | `go run ./cmd/findings-runner signup` | `signup_takeover_findings.txt` |
| 33 | IDOR surface map (**new**) | `go run ./cmd/findings-runner idor` | `idor_surface.txt`, `idor_surface.csv` |
| 34 | OAuth redirect_uri bypass (**new**) | `go run ./cmd/findings-runner oauth` | `oauth_findings.txt` |
| 35 | Race-condition scan (**new**) | `go run ./cmd/findings-runner race` | `race_candidates.txt`, `race_results.txt` |
| 36 | Public bucket guess (**new**) | `go run ./cmd/findings-runner buckets` | `bucket_findings.txt` |
| 37 | Service takeover fingerprints (**new**) | `go run ./cmd/findings-runner takeoversvc` | `takeover_v2_findings.txt` |
| 38 | Deep JS bundle mining (**new**) | `go run ./cmd/findings-runner jsmine` | `js_mine_findings.txt` |
| 39 | Security headers analysis (**new**) | `go run ./cmd/findings-runner secheaders` | `secheaders_findings.txt` |
| 40 | Backup / sensitive-file scan (**new**) | `go run ./cmd/findings-runner backupscan` | `backupscan_findings.txt` |
| 41 | Business-logic surface (**new**) | `go run ./cmd/findings-runner businesslogic` | `business_logic_findings.txt` |
| 42 | Host-header injection (**new**) | `go run ./cmd/findings-runner hostheader` | `hostheader_findings.txt` |
| 43 | Credentialed CORS preflight (**new**) | `go run ./cmd/findings-runner cors2` | `cors2_findings.txt` |
| 44 | Custom nuclei template pass (**new**) | `nuclei -t nuclei-templates-rfuf/` | `nuclei_rfuf_pass.txt` |
| 45 | OWASP coverage and manual plan (**new**) | Built-in evidence mapper | `OWASP_2025_COVERAGE.md`, `candidate_index.jsonl`, `MANUAL_TEST_PLAN.md` |
| 46 | Summary report | (built-in) | `SUMMARY.md`, `findings.md` |

> Stages 14, 15, 16, 17, 18, 19, 20, 21 source from `all_urls_200.txt` —
> only endpoints that responded 200 are scanned. Stage 28 (manual review
> queue) deliberately keeps the unfiltered `all_urls.txt` so the hunter
> can see all historically-interesting paths, not just live ones.

### Performance notes

Certain stages cap their input to prevent the pipeline from hanging on
large targets (thousands of alive hosts):

| Stage | Cap | Reason |
|-------|-----|--------|
| **CORS check** (#22) | Top 500 hosts from `alive.txt`, 20 parallel `curl` workers, `--max-time 5 --connect-timeout 3` | The old serial `while read; do curl; done` loop had no timeout — one stalled host per connection could lock the stage for hours |
| **WAF detection** (#25) | Top 200 hosts | wafw00f issues one HTTP request per host with its own timeouts; 200 hosts is enough to fingerprint the WAF vendor(s) in use |
| **Hidden params** (#27) | Top 100 hosts | arjun fires many requests per host; capping prevents timeout breaches on large target sets |
| **sqlmap_scan** (#14) | 15-minute wall-clock cap via shell `timeout --foreground 15m`; sqlmap input capped to 300 targets via `head -n` | The time-based blind and stacked queries that `--level=3` enables can pin sqlmap against a slow target for 20+ min; the shell-level `timeout --foreground` + `\|\| true` aborts cleanly so the checkpoint records it as completed. Any partial `sqlmap_results/` is preserved on disk. |
| **xss_scan** (#16) | 10-minute wall-clock cap via shell `timeout --foreground 10m`; Gxss amplification bounded by the 200-target ceiling enforced upstream | Gxss expands each XSS candidate into multiple param variants before dalfox even starts; on a 200+ URL list the combined stage can exceed 30 min. The same `timeout --foreground … \|\| true` pattern guarantees no single stage blocks the dashboard. |

## Output Layout

```
~/Desktop/Bug_Bounty/<domain>/
├── .rfuf/
│   ├── checkpoint.json    # resume state
│   └── rfuf.log           # full command log
├── scope.json
├── in_scope_hosts.txt
├── out_of_scope_hosts.txt
├── scoped_subs.txt
├── subs.txt
├── live_subs.txt
├── alive.txt
├── validated_takeovers.txt
├── credentials_found.txt
├── misconfigs.txt
├── auth_results.txt
├── graphql_exposed.txt
├── katana_urls.txt
├── clean_katana_urls.txt
├── trufflehog_results.txt
├── trufflehog_status.json
├── trufflehog_stderr.log
├── trufflehog_version.txt
├── potential_secrets.txt
├── all_urls.txt
├── all_urls_200.txt
├── js_assets.txt
├── js_endpoints.txt
├── jsmap_status.txt
├── nuclei_targets.txt
├── nuclei_targets_status.txt
├── sqlmap_targets.txt
├── sqlmap_status.json
├── sqlmap_results/
├── xss_vulnerabilities.txt
├── nuclei_rce_rce.txt
├── idor_vulnerabilities.txt
├── ssrf_vulnerabilities.txt
├── open_redirect_results.txt
├── lfi_results.txt
├── cors_findings.txt
├── ffuf_results/
├── ffuf_dirs_200.txt
├── manual_business_logic_review.txt
├── SUMMARY.md
└── findings.md
```

## Resume vs. Fresh Run

`rfuf` distinguishes between three modes:

- **`rfuf -d target.com`** (no flag) — always starts a fresh scan. If a
  previous `checkpoint.json` exists for the domain, it is **cleared** and
  every stage re-runs from step 1. Existing output files are overwritten
  in place. The dependency installer *does* run.
- **`rfuf -d target.com -resume`** — continues from the last completed
  stage. Stages already recorded in `checkpoint.json` are skipped, AND the
  dependency installer is bypassed (the on-disk binaries are trusted).
  This is the mode to use after a stop / laptop sleep / Wi-Fi drop.
- **`rfuf -d target.com -skip-install`** — explicit "don't reinstall
  anything" flag for fresh runs (CI, debugging, custom toolchains).
  Combine with `-d` + a fresh work dir for a clean test run that still
  skips the installer.

If a required tool is missing under `-resume` / `-skip-install`, the run
aborts with the missing-tools list and a hint to drop the flag once:
```
[!] missing required tools (run `rfuf -d <domain>` once WITHOUT -resume
    to install): naabu, wafw00f, ghauri
```

This three-mode split is the key behavior fix: previously, a fresh run
silently behaved like a resume (with a missing `-resume` flag treated as
implicit), and a resume silently re-ran the dependency installer (5–15
minutes of wasted setup time before the pipeline started doing real work).

## Tools Orchestrated

`subfinder` · `assetfinder` · `amass` · `dnsx` · `subzy` · `nuclei` ·
`httpx` · `katana` · `trufflehog` · `gau` · `waybackurls` · `gf` ·
`Gxss` · `dalfox` · `sqlmap` · `ffuf` · `seclists` · `jq`

All credit to the original authors — see each project's repository for
licensing. `rfuf` is MIT-licensed glue.

## Project Layout

```
rfuf/
├── cmd/
│   ├── rfuf/              # CLI entrypoint (main.go)
│   ├── filter-testable/   # package main wrapper for internal/filter
│   └── findings-runner/   # package main wrapper that dispatches to every internal/findings/<name>.Run()
├── internal/
│   ├── checkpoint/        # persistent resume state
│   ├── cli/               # live alt-screen dashboard renderer
│   ├── config/            # path resolution (home, gopath, wordlists)
│   ├── executor/          # bash command runner + log writer + auth/env threading
│   ├── filter/            # "is this URL testable?" library
│   ├── installer/         # tool installation & verification
│   │   └── sysinstall/    # one-time system install of the rfuf binary itself
│   ├── pipeline/          # stage definitions + orchestrator
│   ├── summary/           # SUMMARY.md / findings.md generators
│   └── findings/
│       ├── reflection/    # per-URL reflection-site classification
│       ├── paramshape/    # HTTP Parameter Pollution (HPP)
│       ├── authshape/     # cookie + JWT misconfig
│       ├── takeover/      # signup / email-verify flows
│       ├── idor/          # IDOR surface map (per-param roll-up)
│       ├── oauth/         # redirect_uri bypass payloads
│       ├── race/          # concurrent-request race probes
│       ├── buckets/       # S3 / GCS / Azure bucket guess
│       ├── takeoversvc/   # Vercel / Netlify / Fly / AzSWA fingerprints
│       ├── jsmine/        # deep JS-bundle mining (secrets, POSTs, mutations)
│       ├── secheaders/    # CSP / HSTS / X-Frame / Referrer / Permissions
│       ├── backupscan/    # .env / .git / wp-config.bak / db.sql
│       ├── businesslogic/ # pricing / coupon / balance / payment surface
│       ├── hostheader/    # Host-header injection probe
│       ├── cors2/         # credentialed preflight + null-origin
│       └── internal/
│           ├── iohelp/    # ReadLines / WriteLines / BuildAuthHeaders / ApplyAuth
│           └── wafbypass/ # per-WAF tamper catalog (Cloudflare/AWS/Imperva/Akamai/...)
├── nuclei-templates-rfuf/ # custom nuclei overlay (debug, saas tokens, JWT, host-header, CORS)
├── ARCHITECTURE.md        # deep dive into the pipeline / executor / findings layout
├── INSTALL.md             # detailed install / uninstall / fallback guide
├── Makefile
├── LICENSE
└── README.md
```

Internal packages are deliberately kept under `internal/` so they are
not importable by other modules. The `cmd/findings-runner` wrapper is
the single `package main` target the pipeline invokes — `go run`
cannot execute library packages, so every finder is reached through
this dispatcher.

## Roadmap

- [ ] Parallel stages where dependencies allow (currently strictly
  sequential).
- [ ] Configurable output directory via env var or flag.
- [ ] Optional config file for stage toggles / custom nuclei tags.
- [ ] macOS / WSL testing in CI.
- [ ] Webhook notification on pipeline completion.

## Disclaimer

This tool is intended **only** for targets you are explicitly authorized
to test — your own assets, or assets inside the scope of a bug-bounty
program you participate in. The author is not responsible for misuse.

## License

MIT — see [LICENSE](LICENSE).
