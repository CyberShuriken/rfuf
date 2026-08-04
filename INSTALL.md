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
rfuf update                # silent, no prompts — preferred
./rfuf install             # interactive (asks which shell to patch)
```

`rfuf update` rebuilds the current source tree and copies the new
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
rfuf -v           # → rfuf version 2.0.0
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
