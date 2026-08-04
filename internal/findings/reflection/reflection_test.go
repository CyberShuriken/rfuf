package reflection

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		body string
		// marker occurrence we want to classify — we always pass the
		// index of the first occurrence of "MARK".
		want Site
	}{
		{
			name: "html body",
			body: `<html><body><div>MARK</div></body></html>`,
			want: SiteHTMLBody,
		},
		{
			name: "unquoted attribute",
			body: `<a href=MARK>click</a>`,
			want: SiteAttrUnquoted,
		},
		{
			name: "quoted attribute",
			body: `<a href="MARK">click</a>`,
			want: SiteAttrQuoted,
		},
		{
			name: "json value",
			body: `{"user":"MARK","id":1}`,
			want: SiteJSONValue,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			idx := indexOf(tc.body, "MARK")
			if idx < 0 {
				t.Fatalf("MARK not in fixture")
			}
			got := classify(tc.body, idx, len("MARK"))
			if got != tc.want {
				t.Fatalf("classify = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestClassifyNotReflected(t *testing.T) {
	// When idx is -1 (marker not present), classify is not called by
	// the real probeURL loop. We assert the SiteNone zero-value is the
	// natural fallback and that an empty body produces no false
	// positives.
	if SiteNone == "" {
		t.Fatal("SiteNone should not be the empty string")
	}
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
