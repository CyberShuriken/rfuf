// findings-runner is the dispatch wrapper for every Go module under
// internal/findings/<name>/. Prefer the installed `rfuf findings`
// subcommand in production; this binary remains for local `go run`
// during development.
//
//	rfuf findings <finder-name> <workdir>
//	go run ./cmd/findings-runner <finder-name> <workdir>
package main

import (
	"fmt"
	"os"

	"github.com/CyberShuriken/rfuf/internal/findings"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: findings-runner <finder-name> <workdir>")
		os.Exit(2)
	}
	name := os.Args[1]
	workDir := os.Args[2]

	if err := findings.RunFinder(name, workDir); err != nil {
		fmt.Fprintf(os.Stderr, "findings-runner %s: %v\n", name, err)
		if err.Error() == fmt.Sprintf("unknown finder %q", name) {
			os.Exit(2)
		}
		os.Exit(1)
	}
}
