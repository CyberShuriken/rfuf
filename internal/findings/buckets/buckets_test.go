package buckets

import "testing"

func TestBucketHost(t *testing.T) {
	cases := map[string]string{
		"s3":    "https://acme-prod.s3.amazonaws.com/",
		"gcs":   "https://storage.googleapis.com/acme-prod/",
		"azure": "https://acme-prod.blob.core.windows.net/",
	}
	for provider, want := range cases {
		got := bucketHost(provider, "acme-prod")
		if got != want {
			t.Errorf("bucketHost(%q) = %q, want %q", provider, got, want)
		}
	}
}

func TestExtractHost(t *testing.T) {
	cases := map[string]string{
		"https://www.acme.com/path":  "acme.com",
		"http://api.acme.io:8080":    "acme.io",
		"https://acme.com":           "acme.com",
		"https://cdn.acme.com/x.js":  "acme.com",
		"https://deep.sub.acme.com":  "acme.com",
	}
	for in, want := range cases {
		if got := extractHost(in); got != want {
			t.Errorf("extractHost(%q) = %q, want %q", in, got, want)
		}
	}
}
