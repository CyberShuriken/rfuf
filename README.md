# rfuf — Recon Faster U Fool

> One command. Full recon pipeline. Resumable. Self-installing.

`rfuf` is a single-binary orchestration layer that chains together the
bug-bounty recon tools you already use — `subfinder`, `dnsx`, `httpx`,
`katana`, `nuclei`, `sqlmap`, `dalfox`, `ffuf`, and more — into a single
sequential, checkpointed, restartable scan.

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

- **Single command, full pipeline** — subdomain enum → DNS → takeovers →
  HTTP probing → nuclei → crawling → secret scanning → SQLi/XSS/RCE/IDOR
  /SSRF/LFI/open-redirect → CORS → directory brute-force.
- **Crash-safe checkpoints** — every completed step is written to
  `checkpoint.json`. Kill the process, restart, pick up where you stopped.
- **Self-installing** — missing tools are detected and installed via
  `go install` or `apt`. GF patterns are cloned if absent.
- **One-command system install** — `rfuf install` places the binary in
  `/opt/rfuf/` and auto-configures `~/.bashrc` or `~/.zshrc` based on
  your login shell, so `rfuf` is on `$PATH` everywhere after one run.
- **Zero configuration** — no API keys, no YAML, no environment file. Pass
  `-d` and go.
- **Per-domain output directory** — every run writes to
  `~/Desktop/Bug_Bounty/<domain>/` for clean separation between targets.
- **Auto-generated `SUMMARY.md`** — final run produces a Markdown report
  with finding counts and a manual-review checklist.
- **Pure Go, no runtime dependencies** — single static binary, no
  Python, no Node, no Docker.

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
   │  3. Execute pipeline stages sequentially    │
   │     (subfinder → dnsx → nuclei → … → ffuf)  │
   │                                             │
   │     After each successful step:             │
   │       • record step ID in checkpoint.json   │
   └─────────────────────┬───────────────────────┘
                         ▼
              ┌──────────────────────┐
              │  4. Generate SUMMARY │
              └──────────────────────┘
```

## Requirements

| Requirement | Version | Notes |
|-------------|---------|-------|
| Go          | 1.22+   | `sudo dnf install -y golang` |
| Linux       | Any modern distro (tested on Fedora) | macOS likely works but is untested |
| `sudo`      | —       | Required for installing `seclists` and `sqlmap` via `apt`/`dnf` |
| Disk        | ~2 GB   | Tool binaries + nuclei templates + SecLists |

`jq`, `seclists`, and all Go-based tools will be auto-installed on first
run if missing.

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
rfuf -v                   # print version
rfuf -h                   # show help
```

By default all output is written to:

```
~/Desktop/Bug_Bounty/example.com/
```

Override the working directory or target list is intentionally not
exposed — the tool is opinionated by design.

## Pipeline Stages

`rfuf` runs the following stages in order. Every stage is checkpointed;
re-running with `-resume` skips the ones already completed.

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
| 12 | SQLi scan | `gf sqli` → `sqlmap` | `sqlmap_results/` |
| 13 | XSS scan | `gf xss` → `Gxss` → `dalfox` | `xss_vulnerabilities.txt` |
| 14 | RCE scan | `gf rce` → `nuclei` | `nuclei_rce_rce.txt` |
| 15 | IDOR scan | `gf idor` → `nuclei` | `idor_vulnerabilities.txt` |
| 16 | SSRF scan | `gf ssrf` → `nuclei` | `ssrf_vulnerabilities.txt` |
| 17 | Open redirect scan | `gf redirect` → `nuclei` | `open_redirect_results.txt` |
| 18 | LFI scan | `gf lfi` → `nuclei` | `lfi_results.txt` |
| 19 | CORS reflective-origin check | `curl` | `cors_findings.txt` |
| 20 | Directory brute-force | `ffuf` + SecLists | `ffuf_results/`, `ffuf_dirs_200.txt` |
| 21 | Manual review queue | `grep` | `manual_business_logic_review.txt` |
| 22 | Summary report | (built-in) | `SUMMARY.md` |

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
└── SUMMARY.md
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
