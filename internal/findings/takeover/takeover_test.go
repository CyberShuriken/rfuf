package takeover

import "testing"

func TestExtractURLPattern(t *testing.T) {
	body := `<a href="/verify?token=ABC&email=u@x">verify</a>`
	got := extractURLPattern(body)
	if got == "" {
		t.Fatalf("got empty pattern")
	}
	// We don't assert exact shape — both "/verify" and "?token=" can win.
	// The important thing is non-empty.
}

func TestItoa(t *testing.T) {
	cases := map[int]string{0: "0", 1: "1", 42: "42", -7: "-7", 200: "200"}
	for n, want := range cases {
		if got := itoa(n); got != want {
			t.Errorf("itoa(%d) = %q, want %q", n, got, want)
		}
	}
}
