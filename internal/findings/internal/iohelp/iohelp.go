// Package iohelp provides tiny shared helpers used by every finding
// module. Lives in internal/findings/internal/ so the public findings
// package stays a single doc page and the helpers don't get a parallel
// import cycle. Each helper is a one-liner over stdlib; we keep them
// here instead of duplicating across ten modules.
package iohelp

import (
	"bufio"
	"net/url"
	"os"
	"strings"
)

// ValidateURL reports whether a line is a well-formed http(s) URL with a
// parseable host. It exists so a single malformed entry (a bracketed or
// invalid IPv6 literal, a non-http scheme, a bare word) cannot crash a
// downstream consumer — whether that's a Go module dereferencing the parse
// result or an external Python tool (wafw00f/arjun) that aborts the process
// with "ValueError: Invalid IPv6 URL". Callers filter a host/URL list through
// this before handing it to such a consumer.
func ValidateURL(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	// url.Hostname() strips IPv6 brackets; an unparseable literal leaves it
	// empty. Reject anything without a usable host.
	return u.Hostname() != ""
}

// SanitizeURLs returns only the lines of in that pass ValidateURL, preserving
// order. Use it to clean a target list before it reaches a crash-prone tool.
func SanitizeURLs(in []string) []string {
	out := in[:0:0]
	for _, l := range in {
		if ValidateURL(l) {
			out = append(out, l)
		}
	}
	return out
}

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
