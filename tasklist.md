# RFUF Wildcard Reconnaissance and OWASP-Guided Assessment

## Goal

Extend RFUF so an authorized operator can run one wildcard-domain scan that performs bounded reconnaissance first, evaluates the discovered attack surface with the available scanners and finder modules, maps the resulting evidence to OWASP Top 10:2025, and produces an exact manual validation plan for anything that automation cannot safely prove.

RFUF must report **coverage and candidates**, not falsely claim that a category is secure or that a scanner lead is a confirmed vulnerability. Every request remains limited to the explicit scope and the operator’s authorization.

## Definition of done

The work is complete when the following are true:

| Area | Completion requirement | Status |
|---|---|---|
| Wildcard input | `-d example.com` and `-d '*.example.com'` normalize to the same root scope; discovered hosts are filtered before active probing. | ✅ |
| Scope evidence | The run writes `scope.json`, `in_scope_hosts.txt`, and `out_of_scope_hosts.txt` with normalization and filtering metadata. | ✅ |
| Recon pipeline | Reconnaissance completes before vulnerability-oriented stages and retains the existing request caps, timeouts, and checkpoints. | ✅ |
| OWASP mapping | The run writes a complete A01–A10 coverage matrix with `covered`, `partial`, `blocked`, and completed-empty states; unavailable inputs are explained. | ✅ |
| Candidate evidence | Candidate artifacts are indexed in redacted `candidate_index.jsonl` records with category, source, target, confidence, and validation state. | ✅ |
| Manual guidance | The run writes `MANUAL_TEST_PLAN.md` with precise, candidate-specific, non-destructive test instructions and stop conditions. | ✅ |
| Documentation | README.md, ARCHITECTURE.md, IMPLEMENTATION_PLAN.md, INSTALL.md when relevant, and this task list describe the new behavior accurately. | ✅ |
| Validation | `gofmt`, `go vet ./...`, `go test ./...`, `go build ./cmd/rfuf`, and `git diff --check` pass. | ✅ |
| Delivery | Changes are committed and pushed to the selected GitHub repository branch. | ✅ |

## Phase 1 — Normalize and enforce wildcard scope

| Task | Description | Status |
|---|---|---|
| 1.1 | Add a small `internal/scope` package that trims an optional `*.` prefix, lowercases and validates the root domain, and matches exact-root and subdomain hosts without accepting lookalikes such as `example.com.evil.test`. | ✅ |
| 1.2 | Add a `cmd/scope-filter` wrapper that filters newline-delimited candidate hosts or URLs and writes a JSON scope report. | ✅ |
| 1.3 | Add CLI validation and help text explaining wildcard input, authorization, and scope boundaries. | ✅ |
| 1.4 | Add a `scope_guard` pipeline stage between discovery and DNS/HTTP probing. It must write `scope.json`, `in_scope_hosts.txt`, and `out_of_scope_hosts.txt`; downstream active stages must consume only the in-scope stream. | ✅ |
| 1.5 | Pass the normalized root domain to stage environments as `RFUF_DOMAIN` so brute-force and shell stages never operate on the raw wildcard string. | ✅ |
| 1.6 | Add unit tests for wildcard normalization, URL/host parsing, ports, mixed case, trailing dots, IDN-like invalid input, and lookalike domains. | ✅ |

## Phase 2 — Add OWASP coverage and candidate evidence

| Task | Description | Status |
|---|---|---|
| 2.1 | Add an `internal/owasp` package defining A01:2025 through A10:2025, required inputs, relevant RFUF artifacts, and the distinction between automatic checks and manual-only requirements. | ✅ |
| 2.2 | Add an `internal/evidence` or equivalent index writer that emits redacted `candidate_index.jsonl` records. Do not store cookies, bearer tokens, API keys, secrets, or full sensitive response bodies. | ✅ |
| 2.3 | Add finalization-time evidence collection that maps existing candidate files to one or more OWASP categories, preserving source artifact, target, suggested severity, confidence, and `validation_state=candidate`. | ✅ |
| 2.4 | Add stage-health-aware coverage generation. A category is `covered` only when relevant stages completed with usable input; failed, timed-out, blocked, skipped, and completed-empty states must remain distinguishable. | ✅ |
| 2.5 | Add `OWASP_2025_COVERAGE.md` to the summary flow with counts, artifacts, limitations, and missing-input reasons. | ✅ |

## Phase 3 — Generate exact manual test plans

| Task | Description | Status |
|---|---|---|
| 3.1 | Add a manual-test-plan generator that converts IDOR/BOLA, admin-path, OAuth, business-logic, race, JWT, CORS, injection, backup, and exceptional-condition candidates into structured tasks. | ✅ |
| 3.2 | Each task must specify category, target, observed evidence, required identity or role, safe method, expected authorization/control, evidence to capture, and a stop condition. | ✅ |
| 3.3 | Add optional operator inputs for a second cookie/bearer token, role labels, repository/dependency-manifest paths, and a test-only API base URL. Do not guess credentials or create accounts. | ✅ |
| 3.4 | Mark categories that require source code, deployment access, business context, logging access, or two identities as `partial` or `blocked` rather than pretending they were fully assessed. | ✅ |
| 3.5 | Add deterministic tests proving that secrets are redacted and that a two-account authorization task is generated from an IDOR candidate. | ✅ |

## Phase 4 — Update documentation and operator experience

| Task | Description | Status |
|---|---|---|
| 4.1 | Update README.md usage examples, wildcard behavior, new outputs, OWASP coverage semantics, and safe authorization boundary. | ✅ |
| 4.2 | Update ARCHITECTURE.md data flow, stage order, scope guard, evidence schema, and reporting outputs. | ✅ |
| 4.3 | Update IMPLEMENTATION_PLAN.md so it describes the completed foundation and future category-specific modules without claiming complete OWASP automation. | ✅ |
| 4.4 | Update INSTALL.md only if new build/install behavior or command wrappers require it. | ✅ |
| 4.5 | Keep the task list synchronized with the final implementation and mark only verified tasks as complete. | ✅ |

## Phase 5 — Validation and delivery

| Task | Description | Status |
|---|---|---|
| 5.1 | Run `gofmt` on changed Go files and `git diff --check`. | ✅ |
| 5.2 | Run `go test ./...`, including scope, evidence, OWASP, pipeline, summary, and CLI tests. | ✅ |
| 5.3 | Run `go vet ./...` and `go build ./cmd/rfuf`. | ✅ |
| 5.4 | Run a local fixture test using synthetic hosts and URLs only; do not scan a live external target. | ✅ |
| 5.5 | Commit the complete change set and push it to the selected GitHub repository branch. | ✅ |

## Explicit non-goals

This change does not create accounts, guess credentials, spray passwords, bypass MFA, send destructive requests by default, or treat wildcard discovery as permission to scan third-party assets. It does not claim that black-box scanning can fully assess supply-chain failures, insecure design, logging and alerting, or exceptional-condition handling. Those categories require additional source, deployment, workflow, or observability inputs and will be reported as partial or blocked when unavailable.

## Intended final outputs

A successful scan should leave these operator-facing files in the per-domain work directory: `scope.json`, `in_scope_hosts.txt`, `out_of_scope_hosts.txt`, `.rfuf/validation_inputs.json`, `candidate_index.jsonl`, `OWASP_2025_COVERAGE.md`, `MANUAL_TEST_PLAN.md`, `SUMMARY.md`, and `findings.md`. Existing RFUF artifacts remain available for retesting and evidence correlation.
