# rfuf — Recon Faster U Fool

A single-command automated recon + vulnerability scanning pipeline for bug bounty hunting.
Runs subdomain enumeration, DNS resolution, takeover checks, HTTP probing, crawling,
secret scanning, and targeted SQLi/XSS/RCE/IDOR scans — all in one sequential, resumable run.

## Why

Bug bounty recon usually means manually chaining a dozen tools (subfinder → dnsx → httpx →
katana → nuclei → sqlmap...) by hand, every single time, for every new target. `rfuf` automates
that entire chain into one command, with proper checkpointing so a crashed laptop or dead
Wi-Fi doesn't mean starting over.

## Features

- One command, full pipeline: recon → live-host probing → takeover checks → crawling →
  secret scanning → SQLi/XSS/RCE/IDOR targeted scans
- **Resumable** — survives crashes/power loss, picks up exactly where it left off
- **Self-installing** — detects and installs any missing tools automatically
- **Zero config** — no API keys or config files required to get started
- Clean, per-domain output directory structure
- Auto-generated `SUMMARY.md` at the end of every run

## Requirements

- Fedora Linux (or any modern Linux distro), zsh
- Go 1.22+ (`sudo apt install -y golang-go` if you don't have it)
- `seclists` and `jq` (will be auto-installed via `apt` if missing)

## Install

```zsh
git clone https://github.com/CyberShuriken/rfuf.git
cd rfuf
make install
```

This installs the `rfuf` binary to `$(go env GOPATH)/bin`. Make sure that's on your `$PATH`.

## Usage

```zsh
rfuf -d website.com          # run a full recon scan
rfuf -d website.com -resume  # resume an interrupted scan
```

All output is written to:

```
~/Desktop/Bug_Bounty/website.com/
```

## Pipeline & Commands

Below is the sequence of commands `rfuf` executes under the hood:

1. **Subdomain Enum:** `subfinder`, `assetfinder`, `amass`
2. **DNS Resolution:** `dnsx -l subs.txt -silent -o live_subs.txt`
3. **Takeover Check:** `subzy run --targets live_subs.txt --vuln` + `nuclei`
4. **HTTP Probing:** `httpx -l live_subs.txt -silent -o alive.txt`
5. **Vulnerability Scans:** `nuclei` with tags `token-spray,exposure,config,jwt,auth-bypass,default-login`
6. **Crawling:** `katana -list alive.txt -jc -kf all -d 3 -fs rdn -o katana_urls.txt`
7. **Secret Scanning:** `trufflehog filesystem` + `grep` patterns
8. **URL Mining:** `gau` and `waybackurls` to create `all_urls.txt`
9. **Targeted Scans:** `gf` + `nuclei`/`sqlmap`/`dalfox` for SQLi, XSS, RCE, IDOR, SSRF, Open Redirect, LFI
10. **CORS Check:** Reflective-origin check via `curl`
11. **Dir Brute-force:** `ffuf` with `seclists` on all live hosts
12. **Manual Review:** Grep sensitive endpoints to `manual_business_logic_review.txt`

## Tools used under the hood

subfinder · assetfinder · amass · dnsx · subzy · nuclei · httpx · katana ·
trufflehog · gau · waybackurls · gf · Gxss · dalfox · sqlmap · ffuf · seclists · jq

`rfuf` orchestrates these; it doesn't replace them. All credit to their respective authors —
see each project's repo for licensing.

## Changelog

### v2.0.0
- Added auth/JWT scanning and GraphQL exposure scanning.
- Added historical URL mining via `gau` and `waybackurls`.
- Expanded targeted scans to include SSRF, open redirect, and LFI.
- Added a reflective-origin CORS misconfiguration check.
- Added hidden directory brute-forcing via `ffuf` with `seclists`.
- Added manual business-logic review queue generation.
- Updated all targeted scans to use a merged URL list (`all_urls.txt`).

## Disclaimer

For use only against targets you are authorized to test (your own assets, or in-scope
bug bounty programs). The author is not responsible for misuse.

## License

MIT — see [LICENSE](LICENSE)
