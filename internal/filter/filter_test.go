package filter

import (
	"bytes"
	"strings"
	"testing"
)

func TestIsTestableURL(t *testing.T) {
	cases := []struct {
		name string
		url  string
		want bool
	}{
		// Pass-throughs — the URLs we want to scan
		{"search query", "https://example.com/search?q=hello", true},
		{"product id", "https://shop.example.com/product?id=12345", true},
		{"file param", "https://example.com/download?file=report.pdf", true},
		{"multi-param", "https://example.com/api?user=1&action=view", true},
		{"page param", "https://example.com/article?page=2", true},
		{"redirect param", "https://example.com/oauth?redirect_uri=https://app.example.com/cb", true},
		{"wordpress post", "https://blog.example.com/?p=42", true},
		{"numeric id", "https://example.com/order?order_id=9876", true},
		{"edge: param at end, no value after", "https://example.com/api?foo=bar", true},

		// Rejections — static assets
		{"static html", "http://example.com/current/overview.html", false},
		{"static js", "http://example.com/static/app.js", false},
		{"static css", "http://example.com/style.css", false},
		{"static pdf", "http://example.com/manual.pdf", false},
		{"static ico", "http://example.com/favicon.ico", false},
		{"static map (source)", "http://example.com/app.js.map", false},

		// Rejections — analytics/UTM only
		{"utm only", "https://example.com/?utm_source=fb&utm_campaign=pro", false},
		{"_ga only", "https://example.com/?_ga=12345&_gl=1*abc", false},
		{"hubspot hs", "https://example.com/?_hsmi=202157786", false},
		{"fbclid", "https://example.com/?fbclid=abc123", false},
		{"matomo", "https://example.com/?matomo_id=99", false},

		// Rejections — no query param
		{"static homepage", "https://example.com/", false},
		{"static path", "https://example.com/about", false},
		{"static topic", "https://example.com/t/12345", false},

		// Rejections — Discourse public paths (with at least one query param)
		{"discourse topic", "https://community.example.com/t/some-topic/12345?page=1", false},
		{"discourse category", "https://community.example.com/c/bugs/34?page=1", false},
		{"discourse tag", "https://community.example.com/tag/mac?ascending=true", false},
		{"discourse latest", "https://community.example.com/latest?order=activity", false},
		{"discourse search is testable", "https://community.example.com/search?q=hello", true},
		{"discourse assets", "https://community.example.com/assets/app.js?version=1", false},
		{"discourse raw", "https://community.example.com/raw/12345.txt?ref=1", false},

		// Rejections — no fuzzable value (?foo with no =)
		{"trailing question", "https://example.com/search?", false},
		{"empty value", "https://example.com/?", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := IsTestableURL(c.url)
			if got != c.want {
				got2, _ := ClassifyURL(c.url)
				t.Errorf("IsTestableURL(%q) = %v, want %v (reason: %s)", c.url, got, c.want, got2.Reason)
			}
		})
	}
}

func TestClassifyURL_ReasonString(t *testing.T) {
	cases := []struct {
		url    string
		reason string
	}{
		{"http://example.com/app.js", "static asset"},
		{"https://example.com/", "no query param"},
		{"https://example.com/?", "no fuzzable value"},
		{"https://example.com/?_ga=123", "analytics param only"},
		{"https://community.example.com/t/foo/123?ref=1", "discourse public path"},
	}
	for _, c := range cases {
		r, ok := ClassifyURL(c.url)
		if ok {
			t.Errorf("expected %q to be rejected, was passed", c.url)
			continue
		}
		if r.Reason != c.reason {
			t.Errorf("ClassifyURL(%q).Reason = %q, want %q", c.url, r.Reason, c.reason)
		}
	}
}

func TestFilterURLs_CountsAndBuffer(t *testing.T) {
	in := strings.NewReader(`https://example.com/search?q=hello
http://example.com/static/app.js
https://example.com/?_ga=12345
https://example.com/article?page=2
https://example.com/about
`)
	var out bytes.Buffer
	dropped, totalIn, totalOut, err := FilterURLs(in, &out)
	if err != nil {
		t.Fatalf("FilterURLs: %v", err)
	}
	if totalIn != 5 {
		t.Errorf("totalIn = %d, want 5", totalIn)
	}
	if totalOut != 2 {
		t.Errorf("totalOut = %d, want 2", totalOut)
	}
	if dropped["static asset"] != 1 {
		t.Errorf("static asset drops = %d, want 1", dropped["static asset"])
	}
	if dropped["analytics param only"] != 1 {
		t.Errorf("analytics drops = %d, want 1", dropped["analytics param only"])
	}
	if dropped["no query param"] != 1 {
		t.Errorf("no query param drops = %d, want 1", dropped["no query param"])
	}
	if !strings.Contains(out.String(), "search?q=hello") {
		t.Errorf("output missing search URL: %s", out.String())
	}
	if !strings.Contains(out.String(), "article?page=2") {
		t.Errorf("output missing article URL: %s", out.String())
	}
}

func TestFilterURLs_BlankLinesIgnored(t *testing.T) {
	in := strings.NewReader("\n\nhttps://example.com/?id=1\n\n\nhttps://example.com/?id=2\n\n")
	var out bytes.Buffer
	_, totalIn, totalOut, err := FilterURLs(in, &out)
	if err != nil {
		t.Fatalf("FilterURLs: %v", err)
	}
	if totalIn != 2 {
		t.Errorf("totalIn = %d, want 2 (blank lines should not count)", totalIn)
	}
	if totalOut != 2 {
		t.Errorf("totalOut = %d, want 2", totalOut)
	}
}

func TestFilterURLs_LongLine(t *testing.T) {
	// Build a 700-char URL with a query string. Default scanner buffer is
	// 64 KiB so this is fine, but we want to confirm long URLs work.
	// Note: values >200 chars are rejected as "no fuzzable value" — that's
	// correct behavior. We test 150-char value to stay under the cap.
	long := "https://example.com/api?q=" + strings.Repeat("a", 150)
	in := strings.NewReader(long + "\n")
	var out bytes.Buffer
	_, totalIn, totalOut, err := FilterURLs(in, &out)
	if err != nil {
		t.Fatalf("FilterURLs: %v", err)
	}
	if totalIn != 1 || totalOut != 1 {
		t.Errorf("got in=%d out=%d, want 1/1", totalIn, totalOut)
	}
}

func TestFilterURLs_OverlongValueRejected(t *testing.T) {
	// Values >200 chars are excluded — sqlmap/nuclei can't fuzz meaningfully
	// past 200 chars and they bloat the target list.
	long := "https://example.com/api?q=" + strings.Repeat("a", 700)
	in := strings.NewReader(long + "\n")
	var out bytes.Buffer
	dropped, totalIn, totalOut, err := FilterURLs(in, &out)
	if err != nil {
		t.Fatalf("FilterURLs: %v", err)
	}
	if totalIn != 1 || totalOut != 0 {
		t.Errorf("got in=%d out=%d, want 1/0", totalIn, totalOut)
	}
	if dropped["no fuzzable value"] != 1 {
		t.Errorf("dropped = %v, want no-fuzzable-value=1", dropped)
	}
}
