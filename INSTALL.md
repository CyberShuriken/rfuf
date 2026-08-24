# Installing rfuf

This is the one-time setup that makes `rfuf` runnable from any directory
in any new shell, without you touching `$PATH` by hand.

---

## Quick install (recommended)

From inside a clone of this repository:

```bash
./bin/rfuf install
```

> First time? Build once with `make build` so `./bin/rfuf` exists.

Or build and install in a single command (from the repo root):

```bash
make build && ./bin/rfuf install
```

### What `rfuf install` does

1. **Builds the binary** from the current source tree (uses `go build`).
2. **Creates `/opt/rfuf/`** and copies `rfuf` there as
   `/opt/rfuf/rfuf`. Uses `sudo` if you are not already root.
3. **Detects your login shell** from `$SHELL` (zsh or bash).
4. **Asks you to confirm** which shell to patch — defaults to the
   detected one, with options to switch.
5. **Patches `~/.zshrc` or `~/.bashrc`** to add:

   ```bash
   # rfuf: added by rfuf install
   export PATH="/opt/rfuf:$PATH"
   ```

   The marker comment makes the patch idempotent — re-running
   `rfuf install` will not duplicate the line.

After it finishes, open a new terminal (or `source ~/.zshrc` /
`source ~/.bashrc`) and `rfuf` is on your `$PATH` everywhere.

---

## Updating

After `git pull` (or any local rebuild), the binary at
`~/.local/share/rfuf/rfuf` is **not** refreshed automatically — you
must run one of:

```bash
rfuf update                # rebuilds from the RFUF clone and updates the installed binary
./rfuf install             # interactive (asks which shell to patch)
```

`rfuf update` locates the RFUF clone from the current directory, standard clone locations, or `RFUF_SOURCE_DIR`, then rebuilds and copies the new
binary over `~/.local/share/rfuf/rfuf`. It does **not** touch your
shell rc file or the `~/.local/bin/rfuf` symlink (those were already
set up by the first `install`). Run it after every `git pull` so your
next `rfuf -d <domain> -resume` actually uses the latest pipeline /
executor code.

> Without `rfuf update`, the binary on your `$PATH` can be weeks
> behind the source tree, and you'll be running the old executor logic
> (serial `while read; do ffuf` loops, slow `sqlmap` flags, no per-step
> timeouts) against your latest target. This is the single most common
> reason "I pulled the new fixes but they didn't seem to do anything."

---

## Verify the install

```bash
which rfuf        # → /opt/rfuf/rfuf
rfuf -v            # → rfuf version 2.4.4
```

Run a no-op help check from an unrelated directory to confirm:

```bash
cd /tmp && rfuf -h
```

---

## Uninstall

```bash
sudo rm -rf /opt/rfuf
```

Then remove the two-line `rfuf` block from `~/.zshrc` or `~/.bashrc`
(the one starting with `# rfuf: added by rfuf install`).

---

## Manual install (fallback)

If you cannot use `sudo`, or prefer to wire things up by hand:

```bash
# Build to a location you control
make build                  # produces ./bin/rfuf

# Option A: install into your Go bin (still need ~/.bashrc / ~/.zshrc
# on PATH for `go env GOPATH`/bin)
make install
export PATH="$HOME/go/bin:$PATH"

# Option B: copy into a directory you already have on PATH
sudo cp bin/rfuf /usr/local/bin/
```

For a custom location without `sudo`, put the binary anywhere and
add that directory to your shell's `PATH` export.

---

## Requirements recap

- Go 1.22+ (only needed if you build from source)
- `sudo` access for `/opt/rfuf` (the manual fallback above avoids it)
- A POSIX shell — bash or zsh

Recon tools (`subfinder`, `dnsx`, `httpx`, etc.) are **not** installed
by `rfuf install`. Those are bootstrapped automatically the first time
you run `rfuf -d <domain>`. See the main [README](README.md) for the
full pipeline.

---

## Fedora troubleshooting

On Fedora, RFUF passes standard input through to `sudo dnf`, so an interactive terminal can answer the password prompt. Package prechecks use representative executables, avoiding repeated installation attempts for package names such as `ca-certificates` and `openssl` that are not themselves PATH commands.

For non-interactive use, install required system packages before starting RFUF:

```bash
sudo dnf install -y git ca-certificates openssl gcc make jq sqlmap
rfuf -d '*.example.com' -skip-install
```

If the network cannot register an OOB callback, RFUF continues without interactsh after the default 20-second wait. Use `-interactsh-timeout 0` or `-disable-interactsh` when OOB callbacks are unavailable or out of scope. Previous false stage-health errors—`subfinder incomplete (status=failed exit_code=0)`, `amass_enum incomplete (status=failed exit_code=0)`, `jsmap_scrape incomplete (status=failed exit_code=0)`, and `hidden_params_arjun incomplete (status=failed exit_code=0)`—are addressed in RFUF v2.4.5. The artifact classifier now validates final producer outputs, ignores temporary redirect files that a stage explicitly removes, and materializes empty reports for legitimate zero-result runs. Such runs are recorded as `completed_empty`. The safeguard covers `scope_guard`, `jsmap_scrape`, and `hidden_params_arjun`, including `js_assets.txt`, `js_endpoints.txt`, `jsmap_status.txt`, and `hidden_params.txt`.

## Authenticated scan inputs

The scanner does not create accounts, submit signup forms, guess credentials, or bypass MFA. Create an authorized session through the target’s normal login flow, then pass the resulting cookie or bearer token explicitly:

```bash
rfuf -d example.com -auth-cookie 'session=...'
rfuf -d example.com -auth-cookie-file ~/.config/rfuf/session.cookie
rfuf -d example.com -auth-bearer-file ~/.config/rfuf/token
rfuf -d example.com -auth-required -auth-cookie-file ~/.config/rfuf/session.cookie
```

The file-based forms read a local file and use its trimmed contents as one session value. Keep those files protected with normal filesystem permissions. `-auth-required` prevents a run from silently falling back to public-only coverage when authenticated testing is mandatory.

The supplied session is propagated to HTTP probing, crawling, API discovery, JavaScript and manifest downloads, nuclei, SQLmap, and Go finder modules. Authenticated requests remain limited to the explicit scope supplied to RFUF.

The `-d` value controls the mode: `example.com` is exact-only, while `*.example.com` includes the root and proper subdomains. RFUF v2.4.5 includes the exact/wildcard scope distinction, the Amass zero-result artifact fix, the executor-boundary scope_guard empty-artifact fix, the jsmap_scrape resume safeguard, and the hidden_params_arjun temporary-artifact fix. Both use the same normalized root output directory, but `scope.json` records the original input and selected mode. RFUF writes `scope.json`, `in_scope_hosts.txt`, and `out_of_scope_hosts.txt` before active DNS/HTTP probing. Review these files before using scan results; wildcard input is not permission to scan third-party assets.

A resumed run must use the same mode as the original run. To change from `example.com` to `*.example.com`, start a fresh run without `-resume`; RFUF rejects the mismatch to prevent accidental scope expansion.

### Program attribution and scope exclusions

For programs that require researcher attribution, pass the program-provided values explicitly:

```bash
rfuf -d example.com \
  -bug-bounty-username researcher \
  -test-account-email test@example.com \
  -exclude-url-regex '(^|/)(contact|support)(/|$)'
```

RFUF sends these values as `X-Bug-Bounty` and `X-Test-Account-Email` through supported shell and Go-finder requests. The exclusion expression is applied before the canonical URL probe and target-list generation, preventing excluded paths from reaching active downstream scanners.

### Coverage integrity and final artifacts

A successful orchestration message is no longer sufficient evidence of complete coverage. RFUF writes one JSON record per stage under `.rfuf/stages/`, including status, exit code, timeout state, input/output counts, and artifact state. The final outputs are `.rfuf/coverage_report.json`, `CoverageReport.md`, `evidence.jsonl`, `candidate_index.jsonl`, `OWASP_2025_COVERAGE.md`, `MANUAL_TEST_PLAN.md`, and an expanded `SUMMARY.md`.

The final status is `COMPLETE` only when all declared stages finish as `completed` or `completed_empty`. A zero-finding stage is valid when it had valid input and exited successfully. `failed`, `timed_out`, `blocked`, and `skipped` stages are visible and cause an incomplete-coverage error. Partial artifacts are preserved for troubleshooting and resume workflows.

### Authenticated health checks and bounds

Use `-auth-check-url` with an optional `-auth-check-marker` to verify an operator-supplied session before scanning. With `-auth-required`, a failed or mismatched check stops the run. Only boolean state and HTTP status are written to `.rfuf/auth_check.json`; credentials and markers are not stored.

Use `-max-targets` to cap final URL streams and `-max-stage-requests` to configure the request-rate ceiling for scanners that support it. These are explicit bounds for RFUF-controlled streams and compatible tools; they are not a universal budget for every third-party binary.
