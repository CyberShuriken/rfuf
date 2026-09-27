package sysinstall

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInstallNonInteractiveInTemporaryHome(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test source path")
	}
	sourceDir := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "../../.."))
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("RFUF_SOURCE_DIR", sourceDir)
	if err := InstallNonInteractive(); err != nil {
		t.Fatal(err)
	}
	installed := filepath.Join(home, installBin)
	info, err := os.Stat(installed)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		t.Fatalf("installed binary missing or not executable: info=%v err=%v", info, err)
	}
	link := filepath.Join(home, binLink)
	resolved, err := filepath.EvalSymlinks(link)
	if err != nil || resolved != installed {
		t.Fatalf("installed symlink resolved to %q, want %q (err=%v)", resolved, installed, err)
	}
	output, err := exec.Command(installed, "-v").CombinedOutput()
	if err != nil || !strings.Contains(string(output), "rfuf version ") {
		t.Fatalf("installed version check failed: output=%q err=%v", output, err)
	}
	if _, err := os.Stat(filepath.Join(home, ".bashrc")); !os.IsNotExist(err) {
		t.Fatalf("non-interactive install unexpectedly modified shell startup files: %v", err)
	}
}
