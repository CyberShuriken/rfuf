package idor

import "testing"

func TestIsObjectRef(t *testing.T) {
	for _, ok := range []string{"id", "user_id", "order_id", "account"} {
		if !objectRefParams[ok] {
			t.Errorf("objectRefParams[%q] = false, want true", ok)
		}
	}
	for _, no := range []string{"page", "q", "search", "sort", "utm_source"} {
		if objectRefParams[no] {
			t.Errorf("objectRefParams[%q] = true, want false", no)
		}
	}
}
