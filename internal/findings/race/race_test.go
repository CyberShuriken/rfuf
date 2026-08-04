package race

import "testing"

func TestRandHex(t *testing.T) {
	a := randHex(8)
	b := randHex(8)
	if a == b {
		t.Errorf("randHex returned duplicate: %q", a)
	}
	if len(a) != 16 || len(b) != 16 {
		t.Errorf("len = %d,%d, want 16", len(a), len(b))
	}
}
