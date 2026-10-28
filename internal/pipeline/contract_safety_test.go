package pipeline

import (
	"path/filepath"
	"strings"
	"testing"
)

// Every declared contract input is fingerprinted at runtime via fingerprintInputs,
// which rejects ".", absolute paths, and parent traversals. A contract that
// declares such an input compiles and passes the dependency-coverage test but
// aborts the whole pipeline on the first run ("unsafe input artifact path").
// This guards against that class of bug statically.
func TestContractInputsAreFingerprintSafe(t *testing.T) {
	for id, c := range stageContracts {
		for _, in := range c.Inputs {
			clean := filepath.Clean(in)
			if filepath.IsAbs(clean) || clean == "." || strings.HasPrefix(clean, "..") {
				t.Errorf("stage %s declares unsafe input artifact path %q (rejected by fingerprintInputs at runtime)", id, in)
			}
		}
	}
}
