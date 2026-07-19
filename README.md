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

## Pipeline

1. Subdomain enumeration — subfinder, assetfinder, amass
2. DNS resolution — dnsx
3. Subdomain takeover check — subzy + nuclei
4. HTTP probing — httpx
5. Baseline exposure/misconfig scan — nuclei
6. Deep crawl — katana
7. Secret scanning — trufflehog + grep patterns
8. Targeted vuln scans — SQLi (gf + sqlmap), XSS (gf + Gxss + dalfox), RCE (gf + nuclei), IDOR (gf + nuclei)
9. Summary report generation

## Tools used under the hood

subfinder · assetfinder · amass · dnsx · subzy · nuclei · httpx · katana ·
trufflehog · gf · Gxss · dalfox · sqlmap

`rfuf` orchestrates these; it doesn't replace them. All credit to their respective authors —
see each project's repo for licensing.

## Disclaimer

For use only against targets you are authorized to test (your own assets, or in-scope
bug bounty programs). The author is not responsible for misuse.

## License

MIT — see [LICENSE](LICENSE)
