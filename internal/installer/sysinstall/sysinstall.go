// Package sysinstall handles the one-time install of the rfuf binary
// into a user-writable location and wires it onto the user's PATH.
// It is intentionally separate from the recon-tool installer
// (../installer.go) so that each has a single responsibility: that one
// installs subfinder/dnsx/etc.; this one installs rfuf itself.
//
// The install location is ~/.local/share/rfuf/ for the binary and
// ~/.local/bin/ for the symlink, which is the XDG Base Directory
// standard for user-writable executables. No sudo is required.
package sysinstall

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	// installDir is where the rfuf binary lives after install.
	// ~/.local/share/rfuf/ is the XDG standard location for user
	// data; ~/.local/bin/ is on PATH by default on most distros.
	installDir = ".local/share/rfuf"
	installBin = ".local/share/rfuf/rfuf"
	// binLink is the symlink in ~/.local/bin/ that points at the
	// real binary. This is what users actually invoke as `rfuf`.
	binLink = ".local/bin/rfuf"
	// rcMarker is a comment we append to the user's rc file so future
	// installs can detect that we already patched it (idempotency).
	rcMarker = "# rfuf: added by rfuf install"
	// rcExport is the line that actually goes onto $PATH.
	rcExport = "export PATH=\"$HOME/.local/bin:$PATH\""
)

// Install performs the one-time install:
//  1. Builds the current source tree.
//  2. Creates ~/.local/share/rfuf/ and copies the binary in.
//  3. Creates ~/.local/bin/ and symlinks rfuf → ../share/rfuf/rfuf.
//  4. Detects the user's shell and patches the matching rc file so
//     ~/.local/bin is on $PATH in every new shell.
//  5. Prints a summary of what was changed.
func Install() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("could not resolve home directory: %w", err)
	}

	absInstallDir := filepath.Join(home, installDir)
	absInstallBin := filepath.Join(home, installBin)
	absBinLink := filepath.Join(home, binLink)

	// 1. Build.
	fmt.Println("[*] Building rfuf...")
	srcPath, err := buildSelf()
	if err != nil {
		return fmt.Errorf("build failed: %w", err)
	}
	defer os.Remove(srcPath)

	// 2. Create the install directory (user-writable, no sudo).
	if err := os.MkdirAll(absInstallDir, 0755); err != nil {
		return fmt.Errorf("could not create %s: %w", absInstallDir, err)
	}

	// 3. Copy the binary in.
	if err := copyFile(srcPath, absInstallBin); err != nil {
		return fmt.Errorf("could not install binary: %w", err)
	}
	fmt.Printf("[+] Installed binary to %s\n", absInstallBin)

	// 3b. Copy the bundled nuclei-templates-rfuf overlay alongside the
	// binary so `rfuf` can always find its custom templates regardless
	// of where the source tree lives. The pipeline's resolveNucleiTemplatesRfuf
	// checks this adjacent location first.
	templatesSrc := "nuclei-templates-rfuf"
	if info, err := os.Stat(templatesSrc); err == nil && info.IsDir() {
		templatesDst := filepath.Join(absInstallDir, "nuclei-templates-rfuf")
		if err := copyDir(templatesSrc, templatesDst); err != nil {
			fmt.Printf("[!] Warning: could not copy nuclei-templates-rfuf: %v\n", err)
		} else {
			fmt.Printf("[+] Copied nuclei-templates-rfuf to %s\n", templatesDst)
		}
	}

	// 4. Create ~/.local/bin and symlink rfuf → the real binary.
	if err := os.MkdirAll(filepath.Dir(absBinLink), 0755); err != nil {
		return fmt.Errorf("could not create %s: %w", filepath.Dir(absBinLink), err)
	}
	// Compute the symlink target relative to the symlink's directory
	// so the link works even if $HOME contains a symlink itself.
	relTarget, err := filepath.Rel(filepath.Dir(absBinLink), absInstallBin)
	if err != nil {
		return fmt.Errorf("could not compute relative symlink target: %w", err)
	}
	// Remove any existing symlink/file at absBinLink so we don't get
	// EEXIST on re-install. We use os.Remove (not RemoveAll) so we
	// never wipe a real user's file by accident.
	if _, err := os.Lstat(absBinLink); err == nil {
		if err := os.Remove(absBinLink); err != nil {
			return fmt.Errorf("could not remove existing %s: %w", absBinLink, err)
		}
	}
	if err := os.Symlink(relTarget, absBinLink); err != nil {
		return fmt.Errorf("could not symlink %s -> %s: %w", absBinLink, relTarget, err)
	}
	fmt.Printf("[+] Linked %s -> %s\n", absBinLink, relTarget)

	// 5. Detect shell and patch rc file.
	shell, rcPath, err := detectShell()
	if err != nil {
		// Non-fatal: binary is installed, user can wire PATH manually.
		fmt.Printf("[!] Could not detect shell: %v\n", err)
		fmt.Printf("[*] Add $HOME/.local/bin to your $PATH manually if needed.\n")
		return printSummary(false, "", absInstallBin, absBinLink)
	}

	chosen, err := confirmShell(shell, rcPath)
	if err != nil {
		return err
	}
	chosenRC := rcPathFor(chosen)

	if err := patchRC(chosenRC); err != nil {
		return fmt.Errorf("could not patch %s: %w", chosenRC, err)
	}
	fmt.Printf("[+] Ensured $HOME/.local/bin is on PATH via %s\n", chosenRC)

	return printSummary(true, chosen, absInstallBin, absBinLink)
}

// buildSelf runs `go build` against the current package and returns the
// path to the produced binary. We build into a tmp file because the
// caller may be running from inside the source tree — writing to
// ./bin/rfuf would race with the running process on some filesystems.
func buildSelf() (string, error) {
	tmp, err := os.CreateTemp("", "rfuf-build-*.bin")
	if err != nil {
		return "", err
	}
	tmp.Close()

	cmd := exec.Command("go", "build", "-o", tmp.Name(), "./cmd/rfuf")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), nil
}

// RebuildBinary builds the current source tree and replaces the
// binary that `Install()` previously placed at ~/.local/share/rfuf/rfuf.
// No prompts, no rc-file patching, no symlink tinkering — strictly the
// "I just rebuilt from source and want the new code on PATH" verb.
//
// Used by the `rfuf update` subcommand. Idempotent: calling it on top
// of an unchanged tree is a no-op (the file copy just overwrites with
// identical bytes).
func RebuildBinary() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("could not resolve home directory: %w", err)
	}
	absInstallBin := filepath.Join(home, installBin)

	// Ensure the install dir exists — first-ever `rfuf update` on a
	// machine that has never run `rfuf install` will hit this path.
	if err := os.MkdirAll(filepath.Dir(absInstallBin), 0755); err != nil {
		return fmt.Errorf("could not create %s: %w", filepath.Dir(absInstallBin), err)
	}

	srcPath, err := buildSelf()
	if err != nil {
		return fmt.Errorf("build failed: %w", err)
	}
	defer os.Remove(srcPath)

	if err := copyFile(srcPath, absInstallBin); err != nil {
		return fmt.Errorf("could not install binary: %w", err)
	}
	fmt.Printf("[+] Updated binary at %s\n", absInstallBin)
	return nil
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	// Write to a temp file in the same directory as dst, then atomically
	// rename it into place. This avoids the ETXTBSY ("text file busy") error
	// that Linux raises when you try to overwrite an executable that is
	// currently running — which is exactly what `rfuf update` does (it
	// replaces the binary that is executing the update command). On the
	// same filesystem, os.Rename is an atomic unlink+rename at the kernel
	// level and never hits ETXTBSY.
	tmpFile, err := os.CreateTemp(filepath.Dir(dst), ".rfuf-update-*")
	if err != nil {
		// Fallback: if we can't create a temp file, try direct write
		return os.WriteFile(dst, data, 0755)
	}
	tmpPath := tmpFile.Name()
	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmpFile.Chmod(0755); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, dst); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}

// copyDir recursively copies a directory from src to dst.
func copyDir(src, dst string) error {
	if err := os.MkdirAll(dst, 0755); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())
		if entry.IsDir() {
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			data, err := os.ReadFile(srcPath)
			if err != nil {
				return err
			}
			if err := os.WriteFile(dstPath, data, 0644); err != nil {
				return err
			}
		}
	}
	return nil
}

// detectShell reads $SHELL to figure out the user's login shell, and
// returns the matching rc-file path. Only bash and zsh are supported —
// these are the two the user explicitly called out, and they cover
// the vast majority of Linux installs.
func detectShell() (shell, rcPath string, err error) {
	sh := os.Getenv("SHELL")
	switch {
	case strings.HasSuffix(sh, "/zsh"):
		return "zsh", rcPathFor("zsh"), nil
	case strings.HasSuffix(sh, "/bash"), sh == "":
		// Empty $SHELL is unusual but treat it as bash as a sane default.
		return "bash", rcPathFor("bash"), nil
	default:
		return "", "", fmt.Errorf("unsupported shell %q (only bash and zsh are supported)", sh)
	}
}

func rcPathFor(shell string) string {
	home, _ := os.UserHomeDir()
	if shell == "zsh" {
		return filepath.Join(home, ".zshrc")
	}
	return filepath.Join(home, ".bashrc")
}

// confirmShell prints the detected shell and rc file, and lets the user
// override before we patch anything. Empty input accepts the default.
func confirmShell(detected, rcPath string) (string, error) {
	fmt.Printf("[*] Detected shell: %s (rc file: %s)\n", detected, rcPath)
	fmt.Printf("[?] Patch this rc file? [Y/n/switch to bash/switch to zsh]: ")

	reader := bufio.NewReader(os.Stdin)
	answer, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	answer = strings.TrimSpace(strings.ToLower(answer))

	switch answer {
	case "", "y", "yes":
		return detected, nil
	case "n", "no":
		return "", fmt.Errorf("install aborted by user")
	case "switch to bash":
		return "bash", nil
	case "switch to zsh":
		return "zsh", nil
	default:
		// Treat unknown input as "no" — safer than guessing.
		return "", fmt.Errorf("unrecognized response %q — install aborted", answer)
	}
}

// patchRC appends the rfuf PATH export to the given rc file, unless the
// marker comment is already present. Idempotent.
func patchRC(rcPath string) error {
	if data, err := os.ReadFile(rcPath); err == nil {
		if strings.Contains(string(data), rcMarker) {
			fmt.Printf("[*] %s already patched (marker found)\n", rcPath)
			return nil
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	f, err := os.OpenFile(rcPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	// Leading newline so we don't glue onto the previous line, trailing
	// newline so the next append (by the user or a tool) starts cleanly.
	_, err = f.WriteString("\n" + rcMarker + "\n" + rcExport + "\n")
	return err
}

func printSummary(patched bool, shell, installBinPath, binLinkPath string) error {
	fmt.Println()
	fmt.Println("=== rfuf install summary ===")
	fmt.Printf("  binary:  %s\n", installBinPath)
	fmt.Printf("  symlink: %s\n", binLinkPath)
	if patched {
		fmt.Printf("  rc file: %s (shell: %s)\n", rcPathFor(shell), shell)
		fmt.Println()
		fmt.Println("Open a new shell (or `source` your rc file) and run:")
		fmt.Println("  rfuf -v")
	} else {
		fmt.Println("  rc file: (not modified)")
		fmt.Println()
		fmt.Println("To finish setup, add this to your shell rc file:")
		fmt.Printf("  %s\n", rcExport)
	}
	fmt.Println()
	fmt.Println("To uninstall later:")
	fmt.Printf("  rm -rf %s %s\n", installBinPath, binLinkPath)
	fmt.Println("and remove the '# rfuf:' block from your rc file.")
	return nil
}
