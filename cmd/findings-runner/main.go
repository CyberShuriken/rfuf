// findings-runner is the dispatch wrapper for every Go module under
// internal/findings/<name>/. Each module exposes `Run(workDir string)
// error` and writes its own *_<artifact>.txt files. The pipeline
// invokes them as:
//
//	go run ./cmd/findings-runner <finder-name> <workdir>
//
// and the runner dispatches to the right module's Run() function.
//
// This single wrapper means we don't need a per-finder main.go (which
// would add 10 nearly-identical files). Adding a new finder = (1)
// write `Run()` in internal/findings/<name>/ and (2) add a case to
// the switch below. The pipeline wires the new stage by appending a
// Step{ID: "<name>", Command: "go run ./cmd/findings-runner <name> ..."}
// to pipeline.go's GetSteps().
//
// Why a single wrapper rather than per-module `go run
// ./internal/findings/<name>`: a package with package declaration
// `package <name>` cannot be the target of `go run` — `go run` only
// accepts `package main` targets. Going via cmd/findings-runner keeps
// the finder packages as testable libraries (their tests live next to
// them) while presenting a single executable to the pipeline.
package main

import (
	"fmt"
	"os"

	"github.com/CyberShuriken/rfuf/internal/findings/authshape"
	"github.com/CyberShuriken/rfuf/internal/findings/buckets"
	"github.com/CyberShuriken/rfuf/internal/findings/idor"
	"github.com/CyberShuriken/rfuf/internal/findings/jsmine"
	"github.com/CyberShuriken/rfuf/internal/findings/oauth"
	"github.com/CyberShuriken/rfuf/internal/findings/paramshape"
	"github.com/CyberShuriken/rfuf/internal/findings/race"
	"github.com/CyberShuriken/rfuf/internal/findings/reflection"
	"github.com/CyberShuriken/rfuf/internal/findings/takeover"
	"github.com/CyberShuriken/rfuf/internal/findings/takeoversvc"

	// New finders added in Phase 2.
	"github.com/CyberShuriken/rfuf/internal/findings/backupscan"
	"github.com/CyberShuriken/rfuf/internal/findings/businesslogic"
	"github.com/CyberShuriken/rfuf/internal/findings/cors2"
	"github.com/CyberShuriken/rfuf/internal/findings/hostheader"
	"github.com/CyberShuriken/rfuf/internal/findings/secheaders"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: findings-runner <finder-name> <workdir>")
		os.Exit(2)
	}
	name := os.Args[1]
	workDir := os.Args[2]

	run, ok := dispatch[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "findings-runner: unknown finder %q\n", name)
		os.Exit(2)
	}
	if err := run(workDir); err != nil {
		fmt.Fprintf(os.Stderr, "findings-runner %s: %v\n", name, err)
		os.Exit(1)
	}
}

// dispatch maps a finder name to its Run function. Adding a new
// finder = a new entry here + an import above. The pipeline references
// the same string in its Step.Command.
var dispatch = map[string]func(workDir string) error{
	"reflection":    reflection.Run,
	"paramshape":    paramshape.Run,
	"authshape":     authshape.Run,
	"signup":        takeover.Run,
	"idor":          idor.Run,
	"oauth":         oauth.Run,
	"race":          race.Run,
	"buckets":       buckets.Run,
	"takeoversvc":   takeoversvc.Run,
	"jsmine":        jsmine.Run,
	"secheaders":    secheaders.Run,
	"backupscan":    backupscan.Run,
	"businesslogic": businesslogic.Run,
	"hostheader":    hostheader.Run,
	"cors2":         cors2.Run,
}