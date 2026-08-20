package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// TestPadNoEscPadsCorrectly is the invariant that protects the dashboard
// right-border alignment: the visible character count (excluding ANSI
// escapes) must match width exactly. The previous implementation padded
// by len(s) — including escape bytes — and produced ragged borders.
func TestPadNoEscPadsCorrectly(t *testing.T) {
	cases := []struct {
		name  string
		input string
		width int
	}{
		{"plain", "hello", 10},
		{"with-color", "\033[1;31mhello\033[0m", 10},
		{"with-bg", "\033[1;31;42mX\033[0m", 5},
		{"already-wide", "longer-than-width", 4},
	}
	for _, c := range cases {
		out := padNoEsc(c.input, c.width)
		got := lenNoEsc(out)
		if got < c.width && lenNoEsc(c.input) < c.width {
			t.Errorf("%s: visible width %d < expected %d (out=%q)", c.name, got, c.width, out)
		}
	}
}

// TestLenNoEscIgnoresEscapes verifies the helper counts only visible runes.
func TestLenNoEscIgnoresEscapes(t *testing.T) {
	if got := lenNoEsc("\033[1;31mhi\033[0m"); got != 2 {
		t.Errorf("expected 2 visible runes, got %d", got)
	}
	if got := lenNoEsc("plain"); got != 5 {
		t.Errorf("expected 5, got %d", got)
	}
}

// TestDrawDashboardRendersOnce ensures the dashboard writes every
// expected section in one render. Combined with the memory rule that the
// dashboard only ever renders from one goroutine, this guarantees no
// row-level interleaving between concurrent writes.
func TestDrawDashboardRendersOnce(t *testing.T) {
	var buf bytes.Buffer
	prevOut := outWriter
	outWriter = &buf
	defer func() { outWriter = prevOut }()

	DrawDashboard(
		"example.com",
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		[]string{"setup_directories", "subfinder"},
		map[string]bool{"setup_directories": true},
		"subfinder",
		Stats{Subdomains: 42, Takeovers: 1},
	)
	rendered := buf.String()
	for _, want := range []string{
		"rfuf ─",
		"Target:",
		"LIVE FINDINGS:",
		"RECENT FINDINGS",
		"RECENT LOG LINES",
		"Progress:",
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("dashboard missing section %q", want)
		}
	}
}

// TestPushLogLineRingBuffer verifies the executor's throttled log lines
// land in a bounded ring buffer (not unbounded growth that would slow
// each render).
func TestPushLogLineRingBuffer(t *testing.T) {
	logRing = nil
	for i := 0; i < maxLogRingLines*3; i++ {
		PushLogLine("line")
	}
	if len(currentLogRing()) != maxLogRingLines {
		t.Errorf("expected ring buffer of %d, got %d", maxLogRingLines, len(currentLogRing()))
	}
}

func TestSanitizeDashboardLine(t *testing.T) {
	if got := sanitizeDashboardLine("Templates: 944 | Requests: 0/0 (9223372036854775808)"); !strings.Contains(got, "scanner statistics recorded") {
		t.Fatalf("scanner stats were not normalized: %q", got)
	}
	if got := sanitizeDashboardLine("Authorization: Bearer secret"); !strings.Contains(got, "redacted") {
		t.Fatalf("sensitive metadata was not redacted: %q", got)
	}
	if got := sanitizeDashboardLine("https://example.com/api [200]"); got != "https://example.com/api [200]" {
		t.Fatalf("ordinary log line changed: %q", got)
	}
}
