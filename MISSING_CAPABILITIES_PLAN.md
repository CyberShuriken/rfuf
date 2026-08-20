# RFUF Capability Plan

**Status:** Foundation implemented in the current branch
**Scope:** Authorized wildcard reconnaissance and evidence-driven OWASP planning only.

## Goal

RFUF should distinguish a complete scan from a partial or failed scan, enforce the explicit wildcard boundary before active probing, preserve redacted candidate evidence, map observable results to OWASP Top 10:2025, and produce precise manual validation tasks for risks that automation cannot prove.

## Implemented workstreams

| Workstream | Implementation | Acceptance result |
|---|---|---|
| Scope normalization | `internal/scope` validates root/wildcard domains and matches exact-root or proper subdomains only. | Mixed-case, wildcard, trailing-dot, URL, and lookalike tests pass. |
| Scope guard | `scope_guard` runs after discovery and before DNS/HTTP probing. | Scope decisions are persisted in `scope.json` and separate in/out streams. |
| Stage contract | Existing `StageRecord` lifecycle records retain status, dependency, timestamps, exit code, timeout, input/output counts, and skip/error state. | Final coverage distinguishes completed, empty, failed, timed-out, skipped, and blocked stages. |
| Evidence index | Existing redacted evidence indexing covers core and newer finder artifacts. | `evidence.jsonl` contains metadata only and keeps candidates unconfirmed. |
| OWASP coverage | `internal/owasp` defines all A01:2025–A10:2025 categories and maps stage health and evidence. | `OWASP_2025_COVERAGE.md` is generated on finalization. |
| Manual plan | Candidate and category-level tasks include the target, evidence, required identity or role, expected control, evidence capture, and stop condition. | `MANUAL_TEST_PLAN.md` is generated without credential or response-body secrets. |
| Summary integration | Summary links scope, evidence, OWASP, manual-plan, and findings artifacts. | Operators can move from run status to exact next tests. |
| Documentation | README, architecture, installation, implementation, audit, plan, and tasklist are synchronized. | Documentation matches code and output names. |

## Coverage states

A category is `covered` when mapped automated stages complete or complete-empty with usable input. It is `partial` when automation ran but manual validation or additional context is required. It is `blocked` when a relevant stage failed, timed out, was skipped, or needs unavailable source, deployment, identity, workflow, or logging input. A scanner lead remains `candidate` until it is reproduced and impact-confirmed.

## Remaining work

### Identity-aware access control

Accept optional second-session and role labels, generate safe two-account comparisons, and preserve the rule that RFUF never creates accounts, guesses credentials, or performs destructive cross-account actions.

### Source and supply-chain inputs

Add optional repository, lockfile, SBOM, container, and CI-workflow inputs for A03. Keep these separate from black-box wildcard scanning because a domain scan cannot establish build or dependency provenance.

### Cryptographic, logging, and exceptional-condition inputs

Add optional TLS/key-management evidence, test-tenant audit-log checks, and local workflow fixtures for rollback, retry, idempotency, fail-open authorization, and resource limits.

## Safety boundary

The implementation must not add credential guessing, account creation, MFA bypass, uncontrolled cross-account access, destructive requests, denial-of-service behavior, secret-value logging, or automatic report submission. Authentication remains operator-supplied and optional.

## Required validation

```bash
gofmt -w <changed-go-files>
go test ./...
go vet ./...
go build ./cmd/rfuf
go build ./cmd/scope-filter
git diff --check
```

Validation must use local synthetic fixtures. No live external target is part of repository tests.
