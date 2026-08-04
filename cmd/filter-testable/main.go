// filter-testable is the CLI wrapper for internal/filter. The pipeline
// invokes it as `go run ./cmd/filter-testable <workdir>` and the
// command reads from `<workdir>/all_urls_200.txt` (or another file
// passed as arg), runs every line through IsTestableURL, and writes
// pass-through URLs to stdout.
//
// Output is deliberately line-oriented: the pipeline consumes stdout
// into `*_filtered.txt`. Drop-reason counters are NOT printed to stdout
// (would pollute the URL stream); the summary.go uses the per-pipeline
// filter_testable_sqli stage output rather than the per-URL drop
// counts.
//
// Usage:
//
//	cmd/filter-testable <workdir> [input-file]
//
//	<input-file> defaults to <workdir>/all_urls_200.txt when omitted.
package main

import (
	"fmt"
	"os"

	"github.com/CyberShuriken/rfuf/internal/filter"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: filter-testable <workdir> [input-file]")
		os.Exit(2)
	}
	workDir := os.Args[1]
	inPath := workDir + "/all_urls_200.txt"
	if len(os.Args) >= 3 {
		inPath = os.Args[2]
	}

	// FilterFile wants an output path on disk; write to a temp file
	// in workDir and emit its content to stdout so the pipeline can
	// capture into *_filtered.txt via shell redirection.
	outPath := workDir + "/.rfuf/filter-testable.out"
	if err := os.MkdirAll(workDir+"/.rfuf", 0755); err != nil {
		fmt.Fprintf(os.Stderr, "filter-testable: mkdir: %v\n", err)
		os.Exit(1)
	}
	if _, _, _, err := filter.FilterFile(inPath, outPath); err != nil {
		fmt.Fprintf(os.Stderr, "filter-testable: %v\n", err)
		os.Exit(1)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "filter-testable: read %s: %v\n", outPath, err)
		os.Exit(1)
	}
	os.Stdout.Write(data)
}