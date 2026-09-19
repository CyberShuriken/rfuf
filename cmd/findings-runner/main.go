// findings-runner is the dispatch wrapper for every Go module under
// internal/findings/<name>/. Each module exposes `Run(workDir string)
// error` and writes its own *_<artifact>.txt files. The pipeline
// invokes them as:
//
//	go run ./cmd/findings-runner <finder-name> <workdir>
//
// and the runner dispatches to the right module's Run() function.
// This single wrapper means we don't need a per-finder main.go (which
// would add 10 nearly-identical files). Adding a new finder = (1)
// write `Run()` in internal/findings/<name>/ and (2) add a case to
// the switch below. The pipeline wires the new stage by appending a
// Step{ID: "<name>", Command: "go run ./cmd/findings-runner <name> ..."}
// to pipeline.go's GetSteps().
// The runner exits 0 on no-findings so every step
// succeeds even when the input is empty / missing.
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
	"github.com/CyberShuriken/rfuf/internal/findings/specparser"
	"github.com/CyberShuriken/rfuf/internal/findings/bypass403"
	"github.com/CyberShuriken/rfuf/internal/findings/paramsprayer"
	"github.com/CyberShuriken/rfuf/internal/findings/envsecrets"
	"github.com/CyberShuriken/rfuf/internal/findings/gitexposure"
	"github.com/CyberShuriken/rfuf/internal/findings/nextjsbypass"
	"github.com/CyberShuriken/rfuf/internal/findings/s3auditor"
	"github.com/CyberShuriken/rfuf/internal/findings/apiversion"
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
	"specparser":    specparser.Run,
	"paramsprayer":    paramsprayer.Run,
	"bypass403":    bypass403.Run,
	"envsecrets":    envsecrets.Run,
	"gitexposure":   gitexposure.Run,
	"nextjsbypass":  nextjsbypass.Run,
	"s3auditor":     s3auditor.Run,
	"apiversion":    apiversion.Run,
}
