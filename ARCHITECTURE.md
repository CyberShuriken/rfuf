# RFUF Architecture

This document describes how `rfuf` is structured and how the recon pipeline works.
**AI agents: read this before changing pipeline stages, nuclei commands, or target generation.**

## Overview

`rfuf` is a Go CLI that orchestrates external recon tools in a **parallelized dependency graph**.
It does not wrap tool APIs — each stage runs a **bash one-liner** via `internal/executor`.

```
cmd/rfuf/main.go
  → config.ResolvePaths()
  → installer.EnsureTools() / EnsureSeclists()
  → pipeline.Run()
       → checkpoint load/save (.rfuf/checkpoint.json) [Thread-Safe]
       → pipeline.ExecuteGraph()
            → Concurrently run steps whose dependencies are met
            → executor.RunCommand() per stage
       → summary.Generate() → SUMMARY.md
```

Output root: `~/Desktop/Bug_Bounty/<domain>/`

## Package Map

| Package | Role |
|---------|------|
| `cmd/rfuf` | CLI flags: `-d`, `-resume`, `-v`, `-h`, `install` subcommand |
| `cmd/filter-testable` | `package main` wrapper for `internal/filter`; reads stdin, writes pass-through URLs to stdout. Replaces the broken `go run ./internal/filter` reference. |
| `cmd/findings-runner` | `package main` wrapper that dispatches `<finder-name>` to `internal/findings/<name>.Run()`. One wrapper handles all 15+ finder modules. |
| `internal/config` | Resolves work dir, GOPATH/bin, nuclei templates, seclists wordlist |
| `internal/installer` | Auto-installs missing Go/apt tools and GF patterns |
| `internal/pipeline` | **Single source of truth** for all 60+ stage definitions |
| `internal/executor` | Runs `bash -c`, logs to `.rfuf/rfuf.log`, handles Ctrl+C; threads `RFUF_AUTH_*` and `RFUF_OOB_*` env vars |
| `internal/checkpoint` | Persists completed step IDs for `-resume` |
| `internal/summary` | Writes `SUMMARY.md` and severity-grouped `findings.md` |
| `internal/cli` | Live terminal dashboard (stats header during scan) |
| `internal/findings/*` | 15 Go modules implementing the high-signal methodology chain (reflection, paramshape, authshape, signup, idor, oauth, race, buckets, takeoversvc, jsmine, secheaders, backupscan, businesslogic, hostheader, cors2). Each reads inputs from the work dir and writes `*_findings.txt` |
| `internal/findings/internal/iohelp` | Tiny helpers (`ReadLines`, `WriteLines`, `BuildAuthHeaders`, `ApplyAuth`) shared by every finder |
| `internal/findings/internal/wafbypass` | Per-WAF tamper catalog (Cloudflare/AWS/Imperva/Akamai/F5/Barracuda/Sucuri/Fastly/generic). Returns sqlmap `--tamper=` and dalfox `--bypass=` values keyed by detected vendor |
| `nuclei-templates-rfuf/` | Custom nuclei templates: debug-endpoints, saas-tokens-in-html, host-header-injection, jwt-alg-none, cors-credentialed-preflight, null-origin-cors |

## Pipeline Rules (Do Not Break)

1. **Dependency Integrity** — stages run as soon as their `Deps` (dependencies) are met.
2. **Thread-Safe Checkpointing** — `checkpoint.json` is updated via a mutex-protected process.
3. **Fresh run clears checkpoint** — `rfuf -d domain` without `-resume` resets progress.
4. **Step types:**
   - `"default"` — exit code 0 = success
   - `"grep"` — exit code 0 or 1 = success (no matches is OK)
5. **Dashboard Consistency** — The UI uses ANSI escapes to maintain a fixed multi-stage dashboard at the top of the terminal.
6. **Never use serial shell loops against alive.txt** — `while read; do curl; done < alive.txt` with no timeout against thousands of hosts will stall the pipeline for hours. Use `xargs -P N` for parallelism and always add `--max-time`/`--connect-timeout` to every `curl` invocation. This is why `cors_check` was completely rewritten.
7. **Cap large-host stages** — any stage that performs one-request-per-host must cap its input (`head -n N`) to a safe ceiling. Current limits: CORS=500, WAF=200, Arjun=100.
8. **Single-command long-runners need a shell timeout** — `sqlmap`/`dalfox`/`nuclei`-over-thousands-of-urls stages that have no natural early-exit must be wrapped with `timeout --foreground <duration> … ; || true` so they cannot pin the dashboard past the cap. The `|| true` is critical: without it the stage records a failure and the next `-resume` re-runs it from scratch, looping forever. With it, partial output on disk counts as a successful checkpoint.

## Data Flow

```
subfinder/assetfinder/amass → subs.txt
dnsx → live_subs.txt
subzy + nuclei takeovers → validated_takeovers.txt
httpx → alive.txt
nuclei (exposures/misconfigs/auth/graphql) → various *.txt
katana → katana_urls.txt → clean_katana_urls.txt
gau + waybackurls + katana → all_urls.txt
gf + grep → *_targets.txt
tool scan → *_results.txt / sqlmap_results/
ffuf → ffuf_dirs_raw.txt → dirbrute_verify_200 → ffuf_dirs_200.txt
grep business logic → manual_business_logic_review.txt
```

## Vulnerability Scan Stages (Critical)

These stages use **gf patterns** to build target lists from `all_urls.txt`, then run scans.

| Stage | Target file | Scan command pattern |
|-------|-------------|----------------------|
| `sqli_targets` / `sqlmap_scan` | `sqli_targets.txt` | sqlmap batch |
| `xss_targets` / `xss_scan` | `xss_targets.txt` | Gxss → dalfox |
| `rce_targets` / `rce_scan` | `rce_targets.txt` | nuclei `-tags rce` |
| `idor_targets` / `idor_scan` | `idor_targets.txt` | nuclei `-tags idor` |
| `ssrf_targets` / `ssrf_scan` | `ssrf_targets.txt` | nuclei `-tags ssrf` |
| `redirect_targets` / `redirect_scan` | `redirect_targets.txt` | nuclei `-tags redirect` |
| `lfi_targets` / `lfi_scan` | `lfi_targets.txt` | nuclei `-tags lfi` |

### Why tag-based nuclei (not template directories)

**Never** use this pattern for URL-list scans:

```bash
# BAD — runs thousands of templates × every URL → days of runtime
nuclei -l targets.txt -t ~/nuclei-templates/http/vulnerabilities/ -t ~/nuclei-templates/http/cves/
```

**Always** use tags + rate limits for list scans:

```bash
# GOOD — only relevant templates, bounded runtime
nuclei -l rce_targets.txt -tags rce -severity high,critical -rl 150 -c 25 -timeout 10
```

Constants in `pipeline.go`: `nucleiFast`, `maxScanTargets` (5000).

### Target list generation

`all_urls.txt` can contain **100k+ URLs** (gau + wayback + katana).

Rules for `*_targets` steps:

1. Prefer **gf** pattern output first.
2. Optional **grep** must match **query parameters** (`[?&]param=`), not bare words like `file`, `url`, `user`, `run` (those match almost every URL).
3. Always **`sort -u | head -n 5000`** for rce/idor/redirect targets to cap worst-case size.

## All Stage IDs (execution order)

1. setup_directories  
2. subfinder  
3. assetfinder  
4. amass_enum  
5. amass_parse  
6. merge_subs  
7. dnsx_resolve  
8. subzy_takeover  
9. extract_takeover_targets  
10. validate_takeovers  
11. httpx_probe  
12. nuclei_exposures  
13. nuclei_misconfigs  
14. nuclei_auth_scan  
15. nuclei_graphql_scan  
16. katana_crawl  
17. clean_urls  
18. trufflehog_scan  
19. grep_secrets  
20. gau_urls  
21. wayback_urls  
22. merge_all_urls  
23. uro_dedup  
24. url_filter_alive (writes `all_urls_200.txt`; all `*_targets` deps switch here)  
25. sqli_targets  
26. sqlmap_scan (level=3, risk=1, technique=BEUSTQ, **timeout --foreground 15m**)
27. ghauri_sqli (technique=BT, capped)
28. xss_targets
29. xss_scan (**timeout --foreground 10m**)
30. rce_targets  
31. rce_scan  
32. idor_targets  
33. idor_scan  
34. ssrf_targets  
35. ssrf_scan  
36. redirect_targets  
37. redirect_scan  
38. lfi_targets  
39. lfi_scan  
40. cors_check (**xargs -P 20 parallel, top 500 hosts, --max-time 5 --connect-timeout 3** — serial loop was removed, it caused terminal hang on large targets)  
41. dirbrute_ffuf (two-wordlist, recursion depth 2, maxtime 600)  
42. dirbrute_verify_200 (httpx -mc 200 on raw ffuf hits)  
43. waf_detect (capped to top 200 hosts)  
44. port_scan_naabu  
45. hidden_params_arjun (capped to top 100 hosts)  
46. manual_review_queue

## High-Signal Methodology Modules (new)

The default scanner chain (sqlmap, dalfox, nuclei, ffuf) catches the
low-hanging fruit but is **quiet on real targets** because modern apps
use ORMs, CSRF tokens, CSP headers, and rate-limiting that block the
obvious payloads. The pipeline wires up 15 Go finder modules under
`internal/findings/*` that cover the bug classes those scanners miss.

Each module exposes `Run(workDir string) error`, reads from the work
dir (`alive.txt`, `all_urls.txt`, `all_urls_200.txt`, `js_bundles/`,
`tech_fingerprint.txt`, `live_subs.txt`, `waf_detections.txt`), and
writes its own `<name>_findings.txt` (or `<name>_results.txt`).
The pipeline invokes them through `cmd/findings-runner`:

```
go run ./cmd/findings-runner <finder-name> <workdir>
```

The runner is a single `package main` wrapper that dispatches to
the right module's `Run()` — `package main` is required because Go's
`go run` cannot execute a library package. Adding a new finder =
(1) write `Run()` in `internal/findings/<name>/` (2) add a dispatch
entry in `cmd/findings-runner/main.go` (3) add a Step to
`pipeline.go::GetSteps()`.

| # | Stage ID | Finder | Output |
|---|----------|--------|--------|
| 47 | reflection_run | `internal/findings/reflection` | `reflection_findings.txt` |
| 48 | paramshape_run | `internal/findings/paramshape` | `paramshape_findings.txt` |
| 49 | authshape_run | `internal/findings/authshape` | `authshape_findings.txt` |
| 50 | signup_takeover_run | `internal/findings/takeover` | `signup_takeover_findings.txt` |
| 51 | idor_surface_run | `internal/findings/idor` | `idor_surface.txt`, `.csv` |
| 52 | oauth_audit_run | `internal/findings/oauth` | `oauth_findings.txt` |
| 53 | race_scan | `internal/findings/race` | `race_candidates.txt`, `race_results.txt` |
| 54 | bucket_guess_run | `internal/findings/buckets` | `bucket_findings.txt` |
| 55 | takeover_v2_run | `internal/findings/takeoversvc` | `takeover_v2_findings.txt` |
| 56 | js_mine_run | `internal/findings/jsmine` | `js_mine_findings.txt` |
| 57 | secheaders_run | `internal/findings/secheaders` | `secheaders_findings.txt` |
| 58 | backupscan_run | `internal/findings/backupscan` | `backupscan_findings.txt` |
| 59 | businesslogic_run | `internal/findings/businesslogic` | `business_logic_findings.txt` |
| 60 | hostheader_run | `internal/findings/hostheader` | `hostheader_findings.txt` |
| 61 | cors2_run | `internal/findings/cors2` | `cors2_findings.txt` |
| 62 | nuclei_rfuf_pass | `nuclei -t nuclei-templates-rfuf/` | `nuclei_rfuf_pass.txt` |

### Auth threading

Auth values flow through the pipeline via three layers:

1. **CLI flag** (`-auth-cookie`, `-auth-bearer`) → `buildAuthEnv()` in
   `cmd/rfuf/main.go` populates `executor.AuthEnv`.
2. **Executor** (`internal/executor/executor.go::rfufEnv`) appends the
   env map to every child shell's environment as `RFUF_AUTH_COOKIE` /
   `RFUF_AUTH_HEADER`.
3. **Consumers** translate to per-tool flags:
   - Bash stages: `${RFUF_AUTH_COOKIE:+--cookie=$RFUF_AUTH_COOKIE}` /
     `${RFUF_AUTH_HEADER:+--headers=Authorization: $RFUF_AUTH_HEADER}`.
   - Go finders: `iohelp.ApplyAuth(req)` sets the Authorization /
     Cookie headers on each outbound `http.Request`.

Unset = unauthenticated scan (legacy default). The auth threading is
opt-in per scan; nothing leaks into reports or log files.

### WAF bypass chaining

`waf_detect` (capped to 200 hosts) writes `waf_detections.txt`.
`buildWafTamperSnippet()` (a Go function returning a shell preamble)
reads the file at scan time and sets three env vars:

```
WAF_VENDOR         — cloudflare | aws | imperva | akamai | f5 |
                     barracuda | sucuri | fastly | generic | ""
WAF_SQLMAP_TAMPER  — the sqlmap --tamper= value
WAF_DALFOX_BYPASS  — the dalfox --bypass value
```

`sqlmap_scan` and `xss_scan` stages prepend the snippet and
interpolate:

```
${WAF_SQLMAP_TAMPER:+--tamper=$WAF_SQLMAP_TAMPER}
${WAF_DALFOX_BYPASS:+--bypass=$WAF_DALFOX_BYPASS}
```

so when no WAF is detected, the flag is omitted cleanly. The catalog
lives in `internal/findings/internal/wafbypass` and is also
exposed as a Go API for any future Go-stage that wants to read it
directly.

## Safe Change Checklist for Agents

- [ ] New stage added at end of `GetSteps()` slice (or document reorder impact)
- [ ] Step ID is unique and used in checkpoint
- [ ] Output filename documented in `summary.go` if stats needed
- [ ] Nuclei list scans use `-tags`, not `-t` directories
- [ ] Target lists capped when sourced from `all_urls.txt`
- [ ] `"grep"` type set if step uses grep and empty results are OK
- [ ] **No serial shell loop over alive.txt without a per-request timeout** — use `xargs -P` and `--max-time`
- [ ] **Input capped** for any one-request-per-host tool
- [ ] **Long-running single-command stages** (`sqlmap`, `dalfox`, `nuclei` over thousands of targets) wrapped with `timeout --foreground <duration>` + `\|\| true` so they can never block the dashboard past the cap; partial output on disk is the success criterion
- [ ] Run `go build ./cmd/rfuf` after changes

## Hang-Prevention Design

A recon pipeline against a target with thousands of alive hosts has a systemic
failure mode: a stage that iterates hosts serially with no per-request timeout
stalls indefinitely. The executor's global `-step-timeout` is the last-resort
backstop (default: 2h), but the real fix is at the stage level.

**Rules applied to every host-iterating stage:**

| Tool | Mechanism | Cap | Per-request timeout |
|------|-----------|-----|---------------------|
| `curl` (CORS check) | `xargs -P 20` | 500 hosts | `--max-time 5 --connect-timeout 3` |
| `wafw00f` | `head -n N` before tool invocation | 200 hosts | tool's internal timeout |
| `arjun` | `head -n N` before tool invocation | 100 hosts | tool's internal timeout |
| `sqlmap` | `timeout --foreground 15m … ; \|\| true` (shell-level, NOT executor ctx) | 300 targets via `head -n` | `--flush-session --technique=BEUSTQ --level=3 --risk=1` keeps each target bounded |
| `dalfox` (via Gxss) | `timeout --foreground 10m … ; \|\| true` | 200 candidates upstream | internal dalfox deadlines |

**Why shell `timeout --foreground` instead of `Step.Timeout`?**

`Step.Timeout` (enforced by `executor.go` via `context.WithTimeout` + SIGTERM
to the process group) is the *last-resort* backstop. The shell-level
`timeout --foreground` works even on distros where the executor's
process-group killing fires on the wrong PID (mostly seen inside
containers / sub-reapers), and it terminates the entire group tree
including any `Gxss`/`Chromedp` subprocess spawned by dalfox. The `|| true`
fallback in the command ensures the stage exits 0 even on timeout so the
checkpoint records it as completed instead of failing the pipeline — a
15-minute partial sqlmap sweep that found *something* is more useful than a
"stage failed — retrying forever" loop on a wedged backend.

**Anti-pattern (removed):**
```bash
# BAD — no timeout, serial, blocks the pipeline on the first stalled host
while read -r url; do
  curl -s -H "Origin: https://evil.com" -I "$url" | grep -qi "access-control-allow-origin: https://evil.com" && echo "[VULN] $url"
done < alive.txt > cors_findings.txt
```

**Anti-pattern (removed):**
```bash
# BAD — no timeout, serial, blocks the pipeline on the first stalled host
while read -r url; do
  curl -s -H "Origin: https://evil.com" -I "$url" | grep -qi "access-control-allow-origin: https://evil.com" && echo "[VULN] $url"
done < alive.txt > cors_findings.txt
```

**Fixed pattern:**
```bash
# GOOD — 20-way parallel, 5-second max per request, capped to 500 hosts
head -n 500 alive.txt | xargs -P 20 -I{} sh -c \
  'curl -sk --max-time 5 --connect-timeout 3 -H "Origin: https://evil.com" -I "{}" 2>/dev/null \
   | grep -qi "access-control-allow-origin: https://evil.com" && echo "[VULN] {}"' \
  > cors_findings.txt 2>/dev/null; true
```

## Logs & Resume

| File | Purpose |
|------|---------|
| `.rfuf/checkpoint.json` | Completed step IDs, timestamps |
| `.rfuf/rfuf.log` | Full stdout/stderr of every command |
| `SUMMARY.md` | Post-run report |

Resume: `rfuf -d domain -resume` skips steps in checkpoint.
