package takeoversvc

import "testing"

func TestTruncate(t *testing.T) {
	if got := truncate("hello world", 5); got != "hello..." {
		t.Errorf("truncate = %q", got)
	}
	if got := truncate("hi", 100); got != "hi" {
		t.Errorf("truncate short = %q", got)
	}
}
