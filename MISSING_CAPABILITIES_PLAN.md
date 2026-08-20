# RFUF Missing Capabilities Implementation Plan

**Status:** Approved for implementation
**Scope:** Tooling-only reliability and coverage improvements; no live-target execution.

## Goal

Make RFUF distinguish a complete scan from a partial or failed scan, preserve useful partial artifacts without hiding timeouts, enforce scope exclusions at the final target boundary, verify optional authentication sessions, normalize evidence metadata, and make dependency/setup behavior bounded and reproducible.

## Workstreams and acceptance criteria

| Workstream | Implementation | Acceptance criterion |
|---|---|---|
| Stage contract | Add `StageRecord` with stage ID, dependencies, start/end timestamps, exit code, timeout, status, input/output counts, and error/skip reason. Persist one JSON record per stage under `.rfuf/stages/`. | Every graph node has a durable record even when skipped, blocked, times out, or fails to start. |
| Completion gate | Add `coverage_report.json` and `CoverageReport.md` generation. Required stages must finish with `completed` or `completed_empty`; optional skips are explicit. Timeout, failure, blocked dependency, or missing required input makes the run `INCOMPLETE`. | The CLI prints `Pipeline complete` only for a passing coverage gate and prints `Pipeline incomplete` with reasons otherwise. |
| Timeout semantics | Preserve partial output but mark `timed_out=true`; do not convert timeout into an unqualified success. | A timeout is visible in the stage record, summary, dashboard, and process exit status. |
| Input/output metrics | Derive bounded line counts for declared artifact paths after each stage. Keep counts in stage records and a final artifact table. | A zero finding count is distinguishable from zero input, missing artifact, and successful empty output. |
| Dashboard health | Add completed/total, failed, timed-out, skipped, and incomplete indicators. Keep counters typed and bounded; do not parse arbitrary child-tool statistics into integer fields. | Dashboard never displays overflow-looking child counters as RFUF metrics and reports stage health separately. |
| Scope boundary | Add a final `scope_filter` stage after all URL/JS/API merges and before canonical target creation. Apply `RFUF_EXCLUDE_URL_REGEX` and same-scope host filtering there. | No URL in `nuclei_targets.txt`, SQLi/XSS/RCE/SSRF/IDOR target streams, or JS endpoint stream matches the exclusion expression. |
| Auth verification | Add optional `-auth-check-url` and `-auth-check-marker`. Send configured cookie/bearer and program headers; record only boolean, status code, and marker result. | `-auth-check-marker` without a URL fails fast; a failed check is visible and, when `-auth-required` is set, prevents the scan. Secrets never enter logs or reports. |
| Run budget | Add operator-configurable `-max-targets` and `-max-stage-requests` metadata/limits where RFUF controls inputs. Keep existing per-tool rate limits and caps. | Target streams are capped consistently and the report declares the applied limits. Unsupported third-party global budgets are explicitly documented rather than falsely claimed. |
| Dependency reproducibility | Add a version manifest for the installed high-impact tools and tests that installer commands have no unbounded `@latest` for pinned tools. | `rfuf tool-versions` or the manifest reports expected versions; installer behavior is deterministic for the pinned set. |
| Evidence index | Add JSONL evidence records from non-empty finding artifacts with category, source stage, target, severity, confidence, validation state, and redacted evidence reference. | `evidence.jsonl` contains no cookie/token/secret values and separates `candidate` from `confirmed`. |
| Final artifact checks | Add expected-artifact declarations per stage and report missing/empty/optional artifacts. | Final report lists every expected artifact and its state. |
| Tests | Add deterministic unit tests for stage records, timeout classification, coverage gate, scope filtering, auth-check behavior, evidence redaction, and dashboard health. Add a local fixture integration test for the final report. | `go test ./...`, `go vet ./...`, `go build ./cmd/rfuf`, and `git diff --check` pass. |
| Documentation | Update README, ARCHITECTURE, INSTALL, implementation plan, and audit note. | Documentation matches flags, files, status states, and known manual-only limitations. |

## Required stage policy

A stage is `completed` when its command returns zero and its required artifacts are present or intentionally not applicable. A stage is `completed_empty` when it returns zero, had valid input, and produced no findings or candidates. A stage is `failed` for a non-zero command result or executor error. A stage is `timed_out` when the executor deadline fires, even if partial output exists. A stage is `skipped` only when an explicit optional condition is met. A stage is `blocked` when a required dependency did not complete.

The final run status is `COMPLETE` only when all required stages are `completed` or `completed_empty`. It is `INCOMPLETE` for any required failure, timeout, blocked dependency, or missing required artifact. Optional skips remain visible but do not fail the gate.

## Safety boundary

The implementation will not add credential guessing, account creation, MFA bypass, cross-account access, destructive requests, denial-of-service behavior, secret-value logging, or automatic report submission. Authentication remains operator-supplied and optional. Business-logic and IDOR verification remains manual and must use only authorized test accounts.

## Implementation status

Implemented in the current branch: stage lifecycle records under `.rfuf/stages/`; strict `COMPLETE` versus `INCOMPLETE` coverage reporting; explicit timeout, failure, blocked, skipped, and completed-empty states; artifact and input/output metrics; dashboard stage-health counters; child-statistics sanitization; final same-domain and exclusion filtering; authenticated health checks with safe metadata; bounded target and compatible-tool request settings; redacted `evidence.jsonl`; authentication state in `SUMMARY.md`; and deterministic tests covering these behaviors.

Validation completed with `go test ./...`, `go vet ./...`, `go build ./cmd/rfuf`, CLI help verification for all new flags, and `git diff --check`. No live target was used for validation.

The implementation does not claim universal request accounting for tools that provide no compatible rate interface, does not automatically create or authenticate accounts, and does not auto-confirm business-logic or cross-account findings. Those remain operator-controlled manual validation activities.
