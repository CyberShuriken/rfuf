// Package findings hosts the high-signal bug-bounty methodology modules
// that run on top of the recon pipeline. Each module under this package
// is a self-contained finder that reads files in the work dir (alive.txt,
// all_urls.txt, js_bundles/, etc.) and writes one or more
// `*_findings.txt` files that the report generator surfaces.
//
// Conventions:
//   - Each module exposes a Run(workDir string) error function so the
//     pipeline can call it via a `go run ./internal/findings/<name>`
//     shell wrapper. The wrapper is a single line in pipeline.go — see
//     the existing `filterTestableRef` pattern.
//   - Output filenames are stable: `<name>_findings.txt` for the main
//     report and `<name>_<artifact>.csv` for tabular data. The summary
//     generator reads those filenames directly.
//   - Modules are deterministic and short-circuit on missing inputs.
//     A missing alive.txt → empty findings file, exit 0. We never fail
//     the pipeline because a single module had nothing to look at.
//
// Why a separate package instead of inlining into pipeline.go: each
// methodology has 150-300 lines of dedicated logic. Inlining would push
// pipeline.go past 1,200 lines and make the dependency graph harder to
// read. Splitting also lets the hunter run a single module by hand
// (`go run ./internal/findings/reflection` against an existing work dir)
// without re-running the full pipeline.
package findings
