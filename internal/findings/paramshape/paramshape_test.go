package paramshape

import "testing"

func TestShapes(t *testing.T) {
	got := shapes("id")
	want := []string{
		"id=1",
		"id[]=1",
		"id=1&id=2",
		"id=1&ID=2",
		"id=1%00",
	}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i, s := range got {
		if s != want[i] {
			t.Errorf("shapes[%d] = %q, want %q", i, s, want[i])
		}
	}
}

func TestUniqHashes(t *testing.T) {
	if u := uniqHashes(map[string]string{"a": "x", "b": "x", "c": "y"}); u != 2 {
		t.Errorf("uniqHashes = %d, want 2", u)
	}
	if u := uniqHashes(map[string]string{"a": "x", "b": "x"}); u != 1 {
		t.Errorf("uniqHashes = %d, want 1", u)
	}
}
