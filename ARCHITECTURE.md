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
| `internal/config` | Resolves work dir, GOPATH/bin, nuclei templates, seclists wordlist |
| `internal/installer` | Auto-installs missing Go/apt tools and GF patterns |
| `internal/pipeline` | **Single source of truth** for all 39 stage definitions |
| `internal/executor` | Runs `bash -c`, logs to `.rfuf/rfuf.log`, handles Ctrl+C |
| `internal/checkpoint` | Persists completed step IDs for `-resume` |
| `internal/summary` | Writes `SUMMARY.md` with line counts |
| `internal/cli` | Live terminal dashboard (stats header during scan) |

## Pipeline Rules (Do Not Break)

1. **Dependency Integrity** — stages run as soon as their `Deps` (dependencies) are met.
2. **Thread-Safe Checkpointing** — `checkpoint.json` is updated via a mutex-protected process.
3. **Fresh run clears checkpoint** — `rfuf -d domain` without `-resume` resets progress.
4. **Step types:**
   - `"default"` — exit code 0 = success
   - `"grep"` — exit code 0 or 1 = success (no matches is OK)
5. **Dashboard Consistency** — The UI uses ANSI escapes to maintain a fixed multi-stage dashboard at the top of the terminal.

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
ffuf → ffuf_dirs_200.txt
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

## All 39 Stage IDs (execution order)

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
23. sqli_targets  
24. sqlmap_scan  
25. xss_targets  
26. xss_scan  
27. rce_targets  
28. rce_scan  
29. idor_targets  
30. idor_scan  
31. ssrf_targets  
32. ssrf_scan  
33. redirect_targets  
34. redirect_scan  
35. lfi_targets  
36. lfi_scan  
37. cors_check  
38. dirbrute_ffuf  
39. manual_review_queue  

## Safe Change Checklist for Agents

- [ ] New stage added at end of `GetSteps()` slice (or document reorder impact)
- [ ] Step ID is unique and used in checkpoint
- [ ] Output filename documented in `summary.go` if stats needed
- [ ] Nuclei list scans use `-tags`, not `-t` directories
- [ ] Target lists capped when sourced from `all_urls.txt`
- [ ] `"grep"` type set if step uses grep and empty results are OK
- [ ] Run `go build ./cmd/rfuf` after changes

## Logs & Resume

| File | Purpose |
|------|---------|
| `.rfuf/checkpoint.json` | Completed step IDs, timestamps |
| `.rfuf/rfuf.log` | Full stdout/stderr of every command |
| `SUMMARY.md` | Post-run report |

Resume: `rfuf -d domain -resume` skips steps in checkpoint.
