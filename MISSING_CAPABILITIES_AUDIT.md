# RFUF Capability Audit

**Audit date:** 2026-08-20
**Scope:** Tooling-only review and local fixture validation; no live target scan performed.

## Completed capabilities

| Capability | Current behavior | Evidence or output |
|---|---|---|
| Scope mode parsing | `-d example.com` is exact-only; `-d '*.example.com'` is explicit wildcard mode. Both share one validated root directory while preserving mode. | `internal/scope`, CLI validation, scope tests |
| Active scope boundary | `scope_guard` filters the discovered host stream before DNS and HTTP probing. Exact mode retains only the supplied host; wildcard mode retains the root and proper subdomains. Lookalikes and third-party names are rejected. | `scope.json`, `in_scope_hosts.txt`, `out_of_scope_hosts.txt`, `scoped_subs.txt` |
| Stage integrity | RFUF persists lifecycle records with status, timeout, exit code, input/output metrics, and dependency context. | `.rfuf/stages/*.json`, `.rfuf/coverage_report.json`, `CoverageReport.md` |
| Completion gate | `COMPLETE` is reserved for required stages that are `completed` or `completed_empty`; failures, timeouts, blocks, and skips remain visible. | Coverage evaluator and pipeline finalization |
| Evidence normalization | Candidate artifacts are indexed as redacted JSONL metadata with category, source, target, severity, confidence, and validation state. | `evidence.jsonl`, `candidate_index.jsonl` |
| OWASP mapping | Existing scanner and finder artifacts map to A01:2025–A10:2025 with honest `covered`, `partial`, and `blocked` states. | `OWASP_2025_COVERAGE.md` |
| Manual validation guidance | Candidates are converted into non-destructive, candidate-specific tasks with required identity or role, expected control, evidence, and stop conditions. | `MANUAL_TEST_PLAN.md` |
| Authentication replay | Operator-supplied cookies and bearer tokens propagate through supported stages; no credentials are guessed or created. | `-auth-cookie`, `-auth-bearer`, `-auth-required`, auth health check |
| Request bounds | RFUF retains stage timeouts, target caps, parallelism limits, and compatible-tool rate flags. | CLI flags and pipeline constants |
| Documentation | README, architecture, installation, implementation, audit, plan, and tasklist documents describe the same behavior. | Repository Markdown files |

## Deliberate limitations

| Capability | Why it remains limited | Correct next step |
|---|---|---|
| Cross-account access control | A black-box scan cannot infer object ownership or roles from one session. | Supply two authorized test sessions and manually validate the tasks in `MANUAL_TEST_PLAN.md`. |
| Software supply chain failures | A public domain does not expose lockfiles, CI workflows, SBOMs, or signed release provenance. | Provide a repository or dependency-manifest input for a separate source review. |
| Insecure design | Intended business invariants and abuse cases are application-specific. | Model the workflow and test limits, approvals, replay, rollback, and state transitions with synthetic data. |
| Logging and alerting | Security telemetry is usually not observable from HTTP responses. | Use a test tenant and verify audit records, alert routing, retention, and tamper resistance. |
| Exceptional conditions | Fail-open authorization, rollback, idempotency, and partial failures require controlled workflow tests. | Use a local replica or non-production test environment. |
| Universal request accounting | Third-party tools expose different rate and retry controls. | Treat RFUF limits as conservative controls, not a universal global budget. |

## Safety boundary

RFUF must remain limited to assets the operator is explicitly authorized to test. It must not add credential guessing, automatic account creation, MFA bypass, uncontrolled cross-account testing, data exfiltration, denial-of-service behavior, destructive validation, secret-value logging, or automatic report submission.

## Validation status

The current worktree has passed `go test ./...`, `go vet ./...`, `go build ./cmd/rfuf`, `go build ./cmd/scope-filter`, `gofmt`, and `git diff --check`. Validation used synthetic local fixtures and did not send requests to a live external target.
