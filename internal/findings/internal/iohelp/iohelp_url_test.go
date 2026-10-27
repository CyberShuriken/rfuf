package iohelp

import (
	"reflect"
	"testing"
)

func TestValidateURL(t *testing.T) {
	cases := map[string]bool{
		"https://example.com/":        true,
		"http://sub.example.com/a?b=c": true,
		"https://[2001:db8::1]/":      true, // well-formed IPv6
		"https://[::1]:8080/x":        true,
		"":                            false,
		"   ":                         false,
		"ftp://example.com":           false, // non-http scheme
		"example.com/no-scheme":       false,
		"http://[::1":                 false, // malformed IPv6 -> would crash wafw00f/arjun
		"https://":                    false, // no host
	}
	for in, want := range cases {
		if got := ValidateURL(in); got != want {
			t.Errorf("ValidateURL(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestSanitizeURLs(t *testing.T) {
	in := []string{"https://a.com/", "http://[::1", "ftp://b.com", "  ", "http://c.com/x?y=1"}
	got := SanitizeURLs(in)
	want := []string{"https://a.com/", "http://c.com/x?y=1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SanitizeURLs = %v, want %v", got, want)
	}
}
