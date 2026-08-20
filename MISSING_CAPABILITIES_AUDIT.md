# RFUF Missing Capabilities Audit

**Audit date:** 2026-08-20
**Scope:** Tooling-only review; no live target scan performed.

## Confirmed gaps

| Capability | Current behavior | Required improvement |
|---|---|---|
| Stage integrity | `pipeline.Run` marks a step complete after an acceptable process exit, and `grep` treats exit 1 as success. There is no persisted per-stage input/output/timeout/status record. | Add `.rfuf/stages/<step>.json` records and a final `coverage_report.json` with explicit status, exit code, timeout, input/output counts, and skip reason. |
| Completion gate | The orchestrator exits with `Pipeline complete` when all graph nodes are marked complete, including intentional directory-brute skip and soft timeout paths. | Separate `completed`, `partial`, `failed`, `skipped`, and `timed_out`; print `COMPLETE` only when required-stage coverage passes. |
| Timeout semantics | Executor intentionally converts its context timeout to a successful result, which hides partial/timeout state. | Preserve partial output but report `timed_out=true` and make final coverage status incomplete unless the stage is explicitly optional. |
| Stage errors | Errors can be sent through `errChan`, but there is no durable stage error/status artifact or final stage matrix. | Persist start/end, exit, timeout, error, input/output counts, and dependency state for every stage. |
| Dashboard telemetry | `cli.UpdateStats` counts output files only. It does not show stage health or scanner coverage. The screenshot’s large request counter is likely child-tool stats text rather than a typed RFUF metric, but it is not normalized. | Add bounded typed telemetry and a stage-health summary; avoid parsing huge child counters as signed integers. |
| Scope enforcement | `-exclude-url-regex` is applied in the URL probe stage but later merge stages can reintroduce URLs. | Centralize a final scope/exclusion filter after every URL merge and before every active target stream. |
| Auth verification | Cookie/bearer replay exists, but no operator-supplied health-check URL or expected marker confirms the session is authenticated. | Add optional `-auth-check-url` and `-auth-check-marker`; persist only boolean/result metadata and never secret values. |
| Rate/request budget | Individual tool flags and stage timeouts exist, but no run-wide request budget or host rate policy is enforced across tools. | Add conservative operator-configurable run budget metadata and propagate bounded rate settings where supported; do not pretend tools with no common budget are globally governed. |
| Dependencies | Nuclei is pinned and Go toolchain switching is disabled, but most Go tools still use `@latest`. | Add a version manifest/lock documentation and tests; pin at least the high-impact tools or expose a version manifest. |
| Evidence normalization | Findings are collected in many category-specific text files and summarized manually. | Add a normalized JSONL evidence index with source, category, severity, confidence, target, and validation state, without secrets. |
| False-positive state | Dashboard labels any non-empty candidate file as a finding. | Label candidates as `candidate` until manually validated; keep raw artifacts separate from confirmed evidence. |
| Final artifact checks | Summary generation does not enforce expected artifact existence or classify empty inputs. | Add final artifact/coverage validation and include missing/empty/optional state in reports. |
| Business-logic workflows | Existing modules generate BOLA/IDOR and business-logic candidates but do not provide a generic safe workflow recorder or two-account comparison. | Document this as manual-only scope and expose candidate evidence; do not add automatic cross-account access. |

## Current implementation anchors

- `internal/checkpoint/checkpoint.go`: checkpoint only stores completed step IDs.
- `internal/executor/executor.go`: process result and timeout handling.
- `internal/pipeline/pipeline.go`: `Step`, `Run`, command graph, target streams, and shell stages.
- `internal/cli/ui.go`: dashboard stats are line-count based.
- `internal/summary/summary.go`: summary and findings report generation.
- `internal/installer/installer.go`: dependency install definitions.

## Safety boundary

The implementation must remain tooling-only and authorized-scope oriented. It must not add credential guessing, automatic account creation, MFA bypass, uncontrolled cross-account testing, data exfiltration, denial-of-service behavior, or automatic HackerOne submission.

## Implemented in the current worktree

The following gaps have been addressed: durable stage lifecycle records; strict required-stage completion gating; explicit timeout classification; input/output artifact metrics; coverage reports; dashboard stage-health counters; child-statistics and request-metadata sanitization; a final same-domain and exclusion filter; authenticated health-check URL and marker support; bounded target and compatible-tool rate settings; redacted JSONL evidence indexing; final summary authentication state; and deterministic tests for coverage, scope filtering, authentication headers, evidence redaction, dashboard normalization, and finalization.

The remaining limitations are deliberate or dependent on external binaries: RFUF cannot impose a universal request budget on scanners that do not expose one, several upstream tools still resolve their own latest releases, and workflow/IDOR impact validation remains manual and operator-controlled.
