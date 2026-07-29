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
- **Auto-generated `findings.md`** — severity-grouped report with retest
  hints per vulnerability class and a transparent "what was filtered out"
  appendix. Open this first after a run.
- **Pure Go** — single static binary, no runtime dependencies.

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
rfuf -v           # → rfuf version 2.0.0
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
rfuf install              # one-time system install (places binary in /opt/rfuf)
rfuf -d example.com       # fresh full scan
rfuf -d example.com -resume  # continue a previously interrupted scan
rfuf -d example.com -step-timeout 4h  # allow up to four hours per stage
rfuf -v                   # print version
rfuf -h                   # show help
```

By default all output is written to:

```
~/Desktop/Bug_Bounty/example.com/
```

Override the working directory or target list is intentionally not
exposed — the tool is opinionated by design.

Each pipeline stage has a two-hour wall-clock limit by default. This keeps a
single unresponsive upstream tool from leaving the dashboard stuck indefinitely.
Use `-step-timeout <duration>` to adjust it, or `-step-timeout 0` only when you
explicitly want to permit unlimited stage runtime.

## Pipeline Stages

`rfuf` runs the following stages in order. Every stage is checkpointed;
re-running with `-resume` skips the ones already completed. Stages
added per the bb-methodology / security-arsenal playbook are marked
**new**.

| # | Stage | Tool(s) | Output |
|---|-------|---------|--------|
| 1 | Subdomain enumeration | `subfinder`, `assetfinder`, `amass` | `subs.txt` |
| 2 | DNS resolution | `dnsx` | `live_subs.txt` |
| 3 | Subdomain takeover | `subzy` + `nuclei` | `validated_takeovers.txt` |
| 4 | HTTP probing | `httpx` | `alive.txt` |
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
| 22 | CORS reflective-origin check | `curl` | `cors_findings.txt` |
| 23 | Directory brute-force | `ffuf` (small wordlist + recursion) | `ffuf_results/`, `ffuf_dirs_raw.txt` |
| 24 | 200-only verify (**new**) | `httpx -mc 200` on ffuf hits | `ffuf_dirs_200.txt` |
| 25 | WAF detection (**new**) | `wafw00f` | `waf_detections.txt` |
| 26 | Port scan (**new**) | `naabu` | `naabu_ports.txt` |
| 27 | Hidden params (**new**) | `arjun` | `hidden_params.txt` |
| 28 | Manual review queue | `grep` | `manual_business_logic_review.txt` |
| 29 | Summary report | (built-in) | `SUMMARY.md`, `findings.md` |

> Stages 14, 15, 16, 17, 18, 19, 20, 21 source from `all_urls_200.txt` —
> only endpoints that responded 200 are scanned. Stage 28 (manual review
> queue) deliberately keeps the unfiltered `all_urls.txt` so the hunter
> can see all historically-interesting paths, not just live ones.

## Output Layout

```
~/Desktop/Bug_Bounty/<domain>/
├── .rfuf/
│   ├── checkpoint.json    # resume state
│   └── rfuf.log           # full command log
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
├── potential_secrets.txt
├── all_urls.txt
├── all_urls_200.txt
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

`rfuf` distinguishes between two modes:

- **`rfuf -d target.com`** (no flag) — always starts a fresh scan. If a
  previous `checkpoint.json` exists for the domain, it is **cleared** and
  every stage re-runs from step 1. Existing output files are overwritten
  in place.
- **`rfuf -d target.com -resume`** — continues from the last completed
  stage. Stages already recorded in `checkpoint.json` are skipped.

This is the key behavior fix: previously, a missing `-resume` flag was
treated as an implicit resume, which made fresh re-runs silently skip
work. The flag is now an explicit opt-in.

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
│   └── rfuf/              # CLI entrypoint
│       └── main.go
├── internal/
│   ├── checkpoint/        # persistent resume state
│   ├── config/            # path resolution (home, gopath, wordlists)
│   ├── executor/          # bash command runner + log writer
│   ├── installer/         # tool installation & verification
│   │   └── sysinstall/    # one-time system install of the rfuf binary itself
│   ├── pipeline/          # stage definitions + orchestrator
│   └── summary/           # SUMMARY.md generator
├── go.mod
├── INSTALL.md             # detailed install / uninstall / fallback guide
├── Makefile
├── LICENSE
└── README.md
```

Internal packages are deliberately kept under `internal/` so they are
not importable by other modules.

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
