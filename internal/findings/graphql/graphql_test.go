package graphql

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDecodeSchemaDetectsEnabledIntrospection(t *testing.T) {
	body := []byte(`{"data":{"__schema":{"queryType":{"fields":[{"name":"me"},{"name":"orders"}]},"mutationType":{"fields":[{"name":"deleteUser"}]}}}}`)
	q, m, ok := decodeSchema(body)
	if !ok {
		t.Fatal("expected introspection to be detected")
	}
	if len(q) != 2 || len(m) != 1 {
		t.Errorf("queries=%v mutations=%v, want 2 and 1", q, m)
	}
}

func TestDecodeSchemaIgnoresNonGraphQL(t *testing.T) {
	for _, body := range [][]byte{
		[]byte("<html>not graphql</html>"),
		[]byte(`{"errors":[{"message":"introspection disabled"}]}`),
		[]byte(`{"data":{"__schema":{"queryType":{"fields":[]}}}}`), // schema present but no ops
	} {
		if _, _, ok := decodeSchema(body); ok {
			t.Errorf("non-introspection body detected as enabled: %s", body)
		}
	}
}

// Run on an empty work dir must still create its declared outputs (contract).
func TestRunCreatesOutputsOnEmptyWorkdir(t *testing.T) {
	work := t.TempDir()
	if err := Run(work); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"graphql_findings.txt", "graphql_targets.txt", "graphql_candidates.txt"} {
		if _, err := os.Stat(filepath.Join(work, f)); err != nil {
			t.Errorf("declared output %s not created: %v", f, err)
		}
	}
}
