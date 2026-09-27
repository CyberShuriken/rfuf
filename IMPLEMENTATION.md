# RFUF Reliability and Output Recovery Implementation Plan

**Repository:** `CyberShuriken/rfuf`  
**Branch reviewed:** `main` at `93a35118`  
**Prepared:** 2026-09-27  
**Scope:** Tooling-only reliability work for authorized reconnaissance. No live target scanning is part of this plan.

## 1. Executive diagnosis

The empty output problem is caused by multiple independent failure classes, not by one scanner. The current committed branch can compile and pass its existing unit tests, but a real run can still stop before the pipeline, silently skip stages, or report a successful stage while leaving expected artifacts absent.

The most important distinction is:

1. **The reset sandbox copy was not a complete Git checkout.** It had no `.git`, no `go.mod`, no `internal/config`, no `internal/installer/sysinstall`, and no `cmd/filter-testable` or `cmd/findings-runner`. A build from that directory cannot work regardless of pipeline correctness.
2. **The GitHub `main` branch is a different, complete tree.** It contains the missing files and currently passes Go tests, vet, and build.
3. **The committed branch still contains runtime defects.** These explain why an installed binary can run incompletely even though CI-style package tests pass.
4. **The reported run log stopped during dependency bootstrap.** It installed system packages, failed to find the Debian `seclists` package, then began installing `subfinder@latest`. Go reported that the latest release requires Go 1.25 and attempted to download Go 1.26.7. The log never reached pipeline execution. Therefore, that run could not produce scanner artifacts; the correct result should have been a bounded, actionable installer failure rather than an apparent empty scan.

This plan fixes the execution contract first, then artifact guarantees, then dependency reproducibility, and finally adds end-to-end fixture validation.

## 2. Verification performed

### 2.1 Current committed branch

The following checks were run against a fresh clone of `origin/main` at `93a35118`:

| Check | Result | Meaning |
|---|---:|---|
| `GOTOOLCHAIN=local go test ./...` | Pass | Existing package tests compile and pass |
| `GOTOOLCHAIN=local go vet ./...` | Pass | No vet diagnostics in the current tree |
| `GOTOOLCHAIN=local go build ./cmd/rfuf` | Pass | Main CLI builds with the committed source |
| `git diff --check` | Pass | No whitespace errors in the clean clone |
| `gofmt -l` | Reports many files | Formatting is not enforced; the formatter gate is currently absent |
| GitHub tree integrity | Pass | `go.mod`, config, wrappers, and findings packages are tracked |

### 2.2 Reset sandbox copy

The reset copy at `/home/ubuntu/rfuf` was not a Git repository and was missing build-critical tracked files. This was independently confirmed by import-path comparison:

- missing `internal/config`;
- missing `internal/installer/sysinstall`;
- missing `cmd/filter-testable`;
- missing `cmd/findings-runner`;
- missing `go.mod`;
- missing `.git` metadata.

This must be treated as an environment/checkout integrity failure, not as proof that the GitHub branch lacks those files. Future tasks must clone or fetch the repository before testing and must refuse to claim a source build from an incomplete directory.

## 3. Confirmed defects and root causes

### 3.1 Dependency bootstrap can fail before the pipeline starts

**Evidence:** The supplied run log installed `sqlmap` and build packages, could not locate the Debian `seclists` package, and then began `subfinder@latest`. The module required Go 1.25 while the supported local toolchain is Go 1.22.2; Go attempted automatic toolchain download despite the project documentation claiming deterministic local-toolchain behavior.

**Root causes:**

- most installer entries use `@latest`;
- `amass` uses `@master`;
- the installer does not maintain a version manifest or compatibility matrix;
- installer failures are handled inconsistently and can continue into a long build/download operation;
- the `seclists` package is not available in the standard Ubuntu repository, so the package attempt is expected to fail and should immediately use the documented Git fallback;
- dependency installation is not a preflight transaction with a final all-tools verification;
- there is no clear distinction between “bootstrap failed” and “pipeline produced zero findings.”

**Impact:** No stage starts, the user sees no useful target artifacts, and a run can appear hung while a future Go toolchain is downloaded.

### 3.2 Finder execution is inconsistent and breaks from the work directory

The executor sets `cmd.Dir` to the per-domain output directory. The pipeline was partially refactored to use the absolute running binary (`rfuf findings ...`), but several stages still contain:

```text
go run ./cmd/findings-runner <finder> .
```

Confirmed affected stages include:

- `spec_parser`;
- the first `nextjs_bypass_run` and `bypass403` definitions;
- `env_secrets_run`;
- `git_exposure_run`;
- `paramsprayer_run`;
- `api_version_gen`;
- the later `nextjs_bypass_run` definition;
- `s3_audit_run`;
- `idor_run`.

From `~/Desktop/Bug_Bounty/<domain>`, `./cmd/findings-runner` is not the repository path. These commands fail with a missing module/package path unless the work directory happens to contain a source checkout. Some of these commands also append `exit 0`, masking the failure.

**Impact:** Finder output files are absent or empty while the stage can appear successful. The duplicate `nextjs_bypass_run` ID also makes stage identity and checkpoint behavior ambiguous.

### 3.3 Error masking is widespread

Many commands use one or more of the following patterns:

- `set +e` for the entire stage;
- `|| true` after the primary scanner;
- unconditional `exit 0`;
- redirecting stderr to `/dev/null`;
- `if command -v tool; then ...; else : > output; fi`;
- `touch output` after a timeout or error.

These patterns are acceptable only for explicitly optional, no-input, or soft stages, but the current implementation applies them inconsistently. A failed tool and a clean no-finding scan can both become a zero-byte artifact.

**Impact:** `coverage_report.json`, checkpoints, dashboard counters, and the final message do not always explain why output is empty.

### 3.4 Required/optional stage policy is too coarse

`stageRequired` currently returns `true` for every stage. At the same time, many stages are listed in `softStages`, and missing tools are recorded as `skipped` while the scheduler marks the step complete. This produces contradictory semantics:

- every stage is required for coverage;
- some stages are intentionally soft;
- missing tools can be skipped but still count as completed in the scheduler;
- a command may return zero because it deliberately swallowed a failure.

A stage must have an explicit policy: required, optional, or conditional. A missing optional tool should be visible as `skipped_optional`; a missing required tool should fail preflight before scanning.

### 3.5 Output validation covers only a subset of the pipeline

`stageArtifacts` has a small hand-maintained map. It validates outputs for core stages such as `alive.txt`, `all_urls.txt`, `sqlmap_targets.txt`, and a few scanner files, but it does not comprehensively declare outputs for all stages and finder modules.

Examples of output gaps include:

- many finder outputs are not declared in the stage artifact map;
- `high_interest_urls.txt` and related scope streams are not consistently included in the final artifact contract;
- `ffuf_js_results.json`, `waf_detections.txt`, `naabu_ports.txt`, and several technology-specific files have incomplete validation paths;
- output directories such as `js_bundles/`, `endpoints_found/`, `sqlmap_results/`, and `ffuf_results/` are not represented with directory-level state;
- a directory can exist but contain no files, while the report still calls the stage complete;
- a missing artifact can be turned into an empty artifact only for a short allowlist in `ensureZeroResultArtifacts`.

**Impact:** “Output directory is empty” is not reported as a specific stage failure with an input count, exit code, tool version, and reason.

### 3.6 Empty files are not inherently bugs, but they are not explained well enough

A clean scan legitimately produces zero findings. The implementation must not fabricate findings merely to fill directories. It must create a deterministic artifact for every declared stage and record one of:

- `completed_with_findings`;
- `completed_empty` with valid non-zero input;
- `completed_no_input` when the stage had no applicable targets;
- `failed`;
- `timed_out`;
- `skipped_optional`;
- `blocked`.

The current reports mostly expose line counts and do not consistently distinguish these states. That is the direct reason users interpret valid zero results as missing output.

### 3.7 JavaScript/manifest collection still has reliability gaps

The current collector is broader than the original implementation, but it still needs a deterministic contract:

- it is fed from `alive.txt`, whose lines contain httpx metadata; some stages correctly use `awk '{print $1}'`, while others must be audited for raw-line handling;
- asset fetch failures are recorded, but HTTP status/content-type/redirect information is not consistently captured;
- manifest JSON is downloaded but is not uniformly parsed as structured nested data; endpoint extraction is primarily regex-based;
- relative URL resolution for non-root relative paths is simplistic (`BASE/REF`) and can produce incorrect paths when the page URL has a nested path;
- cross-host asset URLs are collected before the final scope filter, increasing noise and possible out-of-scope requests;
- only a fixed set of manifest paths is probed, with no bounded extraction from discovered preload/module metadata;
- the stage can exit successfully with all downloads failing unless its status artifact is interpreted.

### 3.8 Auth/header propagation is not uniformly enforced

The common auth snippet is used by many shell stages, but not all requests use it. Finder stages use environment-based helpers, while several raw `curl` probes and legacy finder invocations bypass the common path.

The implementation also needs a single header policy that documents:

- cookie and bearer replay;
- `X-Bug-Bounty` and `X-HackerOne-Research` attribution;
- `X-Test-Account-Email` attribution;
- redaction rules for logs and metadata;
- whether the request is public-only, authenticated, or auth-check-verified.

Authenticated coverage must not be reported as complete if the auth health check failed or no session was supplied when `-auth-required` was requested.

### 3.9 Scope filtering is applied in multiple places and is vulnerable to drift

The branch has explicit scope parsing and a later URL scope filter, which is good, but the pipeline has several independent streams (`alive`, `all_urls`, `all_urls_200`, `high_interest_urls`, JS endpoints, API specs, finder-generated URLs). Each stream must pass through one final canonical validator before active requests.

The plan must ensure that:

- exact and wildcard scope modes are represented in metadata;
- every URL stream is normalized and checked for host scope;
- exclusion regex is applied after every merge and before every active scanner;
- finder-generated URLs cannot bypass the final scope boundary;
- resume rejects a mode/root mismatch;
- output status includes counts removed by scope and exclusion rules.

### 3.10 Tool and documentation drift exists

The committed code reports version `2.4.10`, while documentation examples still mention `2.4.4`. `INSTALL.md` and `README.md` describe `/opt/rfuf`, while the current installer code uses `~/.local/share/rfuf` and `~/.local/bin/rfuf`. The documentation also describes the pipeline differently from the current stage list.

A tracked ELF binary named `rfuf` exists in the repository. This creates stale-binary risk and makes it easy for a user to execute a binary that does not match the checked-out source. Release artifacts should be built by CI or ignored locally, not committed beside source unless versioned intentionally.

### 3.11 Formatting is not enforced

`go test`, `go vet`, and `go build` pass, but `gofmt -l` reports many Go files. This is not a runtime cause of empty output, but it is a maintainability and review defect. Formatting must become a required check.

## 4. Implementation plan

### Phase 0 — Repository and release integrity

1. Remove the tracked `rfuf` ELF from source control and add build outputs to `.gitignore`.
2. Add a repository preflight command that verifies `.git`, `go.mod`, required command wrappers, nuclei templates, and writable build paths.
3. Make `make build`, `make test`, and `make vet` deterministic and fail on missing prerequisites.
4. Update all docs to one install location and current version.
5. Add CI checks for `gofmt`, `go test`, `go vet`, `go build`, and `git diff --check`.

**Acceptance:** a fresh clone can build from any directory; no checked-in binary can drift from source; docs and CLI version agree.

### Phase 1 — Deterministic dependency installation

1. Create a version manifest for every external tool, not only Nuclei.
2. Replace `@latest` and `@master` with tested versions or a documented compatibility policy.
3. Set `GOTOOLCHAIN=local` explicitly in installer commands and fail fast if the installed Go version is below the supported minimum.
4. Add a bounded install timeout and capture one log per dependency.
5. Use a deterministic fallback for SecLists: package manager, shallow Git clone, or explicit operator-provided path.
6. After installation, run a final `VerifyToolsPresent` check and print a table of installed/missing/version status.
7. Do not start the pipeline unless required tools pass preflight. Optional tools must be declared optional and shown as such.
8. Make package installation order deterministic instead of ranging over a map.

**Acceptance:** an incompatible `@latest` module produces a short actionable error; no automatic future Go download occurs; a missing SecLists package falls back cleanly; no output directory is advertised before the pipeline starts.

### Phase 2 — One execution mechanism for all internal commands

1. Replace every remaining `go run ./cmd/findings-runner ...` with the resolved absolute RFUF binary or a resolved absolute `findings-runner` binary.
2. Use one helper to construct internal commands for `findings`, `filter-testable`, and future internal subcommands.
3. Remove duplicate stage IDs, especially the duplicate `nextjs_bypass_run` definitions.
4. Add a generated test that asserts every `Tool == findings-runner` command uses the resolved runner and contains no work-directory-relative `go run` path.
5. Make finder dispatch return and preserve errors; do not append unconditional `exit 0` to required finder stages.

**Acceptance:** every finder can run from an arbitrary temporary work directory with only the installed binary and its inputs; each finder failure appears in its stage record and causes the correct coverage outcome.

### Phase 3 — Explicit stage contracts and output manifest

1. Extend `Step` with an explicit policy: required/optional/conditional, input contract, output contract, and whether empty input is valid.
2. Replace command-string output inference as the primary source of truth with declarative artifact manifests.
3. Declare every output file and directory for every stage, including all finder modules and scanner result folders.
4. Capture artifact state with `exists`, `kind`, `bytes`, `lines/files`, `created_at`, and `content_status`.
5. Materialize zero-result files only where the stage contract says an empty file is valid; materialize status JSON for directory outputs.
6. Record tool exit code, timeout, stderr log path, tool version, input count, output count, and skip reason.
7. Never classify a missing required output as `completed_empty` merely because the shell exited 0.
8. Preserve partial output on timeout, but classify the stage as `timed_out` unless explicitly optional.

**Acceptance:** every stage produces a machine-readable record; every declared artifact is either present or explicitly marked not applicable; empty directories are reported as `no_input`, `failed`, or `completed_empty` with evidence.

### Phase 4 — Correct scheduler and coverage gate

1. Separate process completion from stage completion.
2. Treat a missing required tool as preflight failure, not as a completed skipped step.
3. Make optional tools produce `skipped_optional` records without failing the run.
4. Make dependency failures produce `blocked` records for all downstream stages.
5. Make timeout status authoritative even if a shell wrapper returns 0.
6. Ensure all stage-record writes are checked and propagated; do not discard write errors with `_ =`.
7. Ensure `stopAndWait` finalization always writes coverage, evidence, summary, and diagnostic metadata.
8. Make final status one of `COMPLETE`, `INCOMPLETE`, or `BOOTSTRAP_FAILED`, and use matching exit codes.
9. On resume, invalidate stages whose input contract, tool version, or command hash changed.

**Acceptance:** a single failed required stage cannot produce “Pipeline complete”; a missing tool cannot silently generate an empty result; resume never trusts an artifact generated by a different command contract.

### Phase 5 — Canonical target and scope pipeline

1. Normalize all host and URL inputs before merging.
2. Feed every source—subfinder, crt.sh, Amass, crawl, gau, Wayback, API specs, manifests, and JS endpoints—through one canonical stream builder.
3. Apply exact/wildcard scope validation and exclusion regex after every merge and immediately before active requests.
4. Keep separate, documented streams for base hosts, all URLs, live URLs, high-interest statuses, JS assets, API endpoints, and vulnerability targets.
5. Record source provenance for each URL so users can tell whether a target came from crawl, history, API spec, or JS.
6. Enforce target caps after deduplication and report how many candidates were dropped.
7. Ensure no finder-generated or manifest-generated URL bypasses scope validation.

**Acceptance:** a fixture containing in-scope, out-of-scope, excluded, duplicate, redirect, 401, and 403 URLs yields deterministic final streams with no excluded or out-of-scope target.

### Phase 6 — JavaScript and manifest reliability

1. Parse HTML `script`, `link`, preload, modulepreload, and inline JSON references.
2. Resolve URLs using a standards-correct URL resolver rather than string concatenation.
3. Probe bounded Next.js and conventional manifest paths plus discovered manifest references.
4. Parse JSON manifests recursively and extract only URL/path-shaped values.
5. Download assets with common auth/program headers, record status/content type/size/hash, and reject cross-scope hosts.
6. Store per-asset metadata and per-host failure reasons.
7. Extract endpoints with a parser that distinguishes absolute URLs, path literals, API route templates, and non-URL strings.
8. Add a fixture containing nested Next.js manifests, static chunks, source maps, relative assets, auth-required assets, and an out-of-scope asset.

**Acceptance:** the fixture produces expected `js_assets`, downloaded bundle/manifest files, endpoint provenance, and explicit failed-asset records without out-of-scope requests.

### Phase 7 — Authentication and attribution contract

1. Centralize request construction for shell and Go finder stages.
2. Support cookie, bearer, and protected local-file input without printing secret values.
3. Apply required program headers consistently to every supported HTTP request.
4. Add auth health-check metadata with boolean verification, status, and safe error classification.
5. Mark reports as `public`, `authenticated_unverified`, or `authenticated_verified`.
6. Never claim private-surface coverage when auth was absent, failed, or unverified under `-auth-required`.
7. Add fixture tests that assert headers arrive and that logs, evidence, stage records, and summaries do not contain cookie/token values.

**Acceptance:** authenticated fixture requests receive the exact configured headers; secret values are absent from all persisted artifacts; `-auth-required` stops before scanning when verification fails.

### Phase 8 — Scanner-specific reliability

1. Keep SQLmap input as a materialized bounded file and record target count, command, timeout, exit code, and result folder state.
2. Make Nuclei, Dalfox, Ghauri, FFUF, Naabu, Arjun, TruffleHog, and WAF detection use declared input/output contracts.
3. Capture stderr separately for every external tool; only suppress expected noisy output after it is persisted.
4. Validate that tool-specific output formats are parseable before classifying a stage as complete.
5. Add per-tool timeout and rate-limit metadata to the run report.
6. For TruffleHog, distinguish `not_installed`, `no_inputs`, `completed_clean`, `completed_findings`, and `scan_error`.
7. Do not use `|| true` on a required scanner without writing a structured failure status.

**Acceptance:** fake executables cover success, clean, non-zero, timeout, malformed output, and missing-binary cases; each case maps to one unambiguous stage status.

### Phase 9 — Reports, cleanup, and documentation

1. Generate an artifact manifest alongside `SUMMARY.md`, `findings.md`, `CoverageReport.md`, `evidence.jsonl`, and OWASP/manual-review reports.
2. Show zero findings separately from missing output and no input.
3. Include stage ID, status, input/output counts, tool version, and diagnostic log path in reports.
4. Make cleanup opt-in only; never delete diagnostic logs automatically after a failed run.
5. Update `README.md`, `ARCHITECTURE.md`, `INSTALL.md`, and all implementation/audit notes in the same change.
6. Document that empty findings are valid, but missing artifacts and failed stages are not silently converted to success.

**Acceptance:** a user can open one summary and identify exactly why any output file or directory is empty, which stages ran, and what must be retried.

## 5. Test matrix

### Unit tests

- command construction never contains work-directory-relative `go run` for production stages;
- stage IDs are unique;
- every stage has a policy and artifact contract;
- scope and exclusion filtering is deterministic;
- target caps apply after deduplication;
- auth headers are propagated and redacted;
- SQLmap uses a named target file;
- timeout/failure/skip/blocked statuses are distinct;
- missing required outputs fail the stage;
- empty valid inputs produce `completed_no_input` or `completed_empty`;
- evidence and reports contain no secrets;
- cleanup does not remove failure diagnostics.

### Local integration fixtures

Run a local HTTP fixture with:

- multiple in-scope hosts;
- HTML referencing conventional JS, Next.js chunks, manifests, preload/module assets, and a relative nested asset;
- 401/403 auth-walled endpoints;
- a manifest with nested route data;
- an out-of-scope asset and an excluded URL;
- deterministic fake scanner executables placed on `PATH`.

Assertions:

1. dependency preflight succeeds using the fake tools without network installation;
2. every planned stage writes a status record;
3. every expected output file/directory has a contract state;
4. all canonical target lists are scoped and exclusion-filtered;
5. JS/API targets reach the endpoint scan stages;
6. a deliberate scanner failure produces `INCOMPLETE`, never `COMPLETE`;
7. a clean scan produces non-empty status metadata even when findings are zero;
8. resume reruns invalidated or failed stages and preserves diagnostics.

### Required commands

```bash
GOTOOLCHAIN=local gofmt -w $(find . -name '*.go' -type f)
GOTOOLCHAIN=local go test ./...
GOTOOLCHAIN=local go vet ./...
GOTOOLCHAIN=local go build ./cmd/rfuf
GOTOOLCHAIN=local go build ./cmd/findings-runner
GOTOOLCHAIN=local go build ./cmd/filter-testable
git diff --check
```

The formatting command should be used only after reviewing the resulting diff; CI should use `gofmt -l` and fail if it prints files.

## 6. Safety and authorization boundary

This plan does not add credential guessing, account creation, MFA bypass, password spraying, destructive testing, denial-of-service behavior, cross-account access without explicit operator control, data exfiltration, or automatic report submission. Authenticated testing remains limited to operator-supplied sessions and authorized scope. Business-logic and IDOR validation remain manual and require the operator’s own authorized test identities.

## 7. Definition of done

- A fresh clone builds from any working directory.
- Dependency bootstrap is versioned, bounded, and never silently switches Go toolchains.
- Every internal finder runs through one absolute, tested dispatch path.
- Every stage has explicit dependencies, policy, inputs, outputs, and status.
- Empty results are explained rather than hidden or fabricated.
- Required-stage failures, timeouts, missing tools, and blocked dependencies make the run `INCOMPLETE`.
- Canonical target streams are scope-safe, deduplicated, capped, and provenance-aware.
- Authenticated request propagation and secret redaction are covered by fixtures.
- `SUMMARY.md` and all Markdown documentation match the actual CLI, install paths, stage list, and artifact layout.
- Tests, vet, builds, formatting, and diff checks pass.
- The completed implementation is committed and pushed to `origin/main`.

## 8. Baseline conclusion (reviewed commit)

This section records the diagnosis at the reviewed commit, before the worktree changes described below. It is historical context; use Section 9 for current implementation and verification status.

## 9. Worktree implementation status (2026-09-28)

The worktree now includes pinned installer references and tests rejecting floating `@latest`, `@master`, and latest-release URLs; optional-tool installation handling; propagated stage-record and checkpoint persistence errors; an embedded declarative contract for every pipeline stage with dependency artifacts recorded as inputs; command, tool identity/version, dependency, contract, and artifact checks for resume; authenticated health metadata in coverage reports; and auth/log redaction checks.

JavaScript collection is a bounded built-in Go stage. Its local fixture exercises authenticated page and asset requests, recursive manifests, endpoint provenance, HTTP failure metadata, exclusions, and out-of-scope references routed to loopback. Existing pipeline fixtures cover scope guarding, final URL exclusion/filtering, zero-input artifact creation, and resume invalidation. Installer, contract, and executor tests cover dependency pins, persistence errors, timeouts, and secret redaction. No installer dependency bootstrap or live target scan was run.

The implementation is reliability-improved, but it is **not being declared production-ready**. No live target was scanned, and successful local fixtures cannot establish behavior across real scanner versions, target responses, or authorization policies. The local verification results and commit state are reported with this change; a real authorized validation remains outstanding.
