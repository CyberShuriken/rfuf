// Package iohelp provides tiny shared helpers used by every finding
// module. Lives in internal/findings/internal/ so the public findings
// package stays a single doc page and the helpers don't get a parallel
// import cycle. Each helper is a one-liner over stdlib; we keep them
// here instead of duplicating across ten modules.
package iohelp

import (
	"bufio"
	"os"
	"strings"
)

// ReadLines reads a file and returns its non-blank lines. Missing file
// is not an error — it returns (nil, nil). Every module starts with
// `hosts, _ := iohelp.ReadLines(workDir+"/alive.txt")` and the
// module becomes a no-op when the input isn't there yet.
func ReadLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var out []string
	scanner := bufio.NewScanner(f)
	// Default 64KB is fine; recon URLs are well under that. Buffers can
	// grow up to 1MB for the rare long-line case.
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			out = append(out, line)
		}
	}
	return out, scanner.Err()
}

// WriteLines writes a slice to path atomically. We write to path+".tmp"
// and rename so a crash mid-write can't leave a half-written findings
// file that the summary generator would pick up and count as a real hit.
func WriteLines(path string, lines []string) error {
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	for _, l := range lines {
		if _, err := w.WriteString(l); err != nil {
			f.Close()
			return err
		}
		if err := w.WriteByte('\n'); err != nil {
			f.Close()
			return err
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
