# RFUF Wildcard Scope and OWASP-Guided Assessment Plan

## Purpose

RFUF is a staged reconnaissance and candidate-generation tool. This plan defines how it accepts a root or wildcard domain, enforces the active-scan boundary, maps observable evidence to OWASP Top 10:2025, and tells an authorized researcher exactly what still requires manual validation.

The implementation deliberately does **not** claim that a black-box scan proves every OWASP category. Supply-chain failures, insecure design, logging and alerting, exceptional conditions, and parts of cryptographic and authentication review require source, deployment, workflow, identity, or observability inputs.

## Completed foundation

| Capability | Implementation | Output |
|---|---|---|
| Wildcard normalization | `internal/scope.NormalizeDomain` accepts `example.com` and `*.example.com`, lowercases and validates the root, and shares one stable work directory. | Normalized domain in CLI output and checkpoint path |
| Active scope enforcement | `scope_guard` filters discovery results to the exact root or proper subdomains before DNS and HTTP probing. | `scope.json`, `in_scope_hosts.txt`, `out_of_scope_hosts.txt`, `scoped_subs.txt` |
| Standalone scope utility | `cmd/scope-filter` filters host/URL files and emits a JSON report for local workflows and fixture tests. | Filtered file plus optional report |
| Redacted evidence | Existing evidence indexing is extended to newer finder artifacts; credentials and response bodies are not copied. | `evidence.jsonl` |
| OWASP mapping | `internal/owasp` defines A01:2025 through A10:2025, maps candidates and stage health, and distinguishes `covered`, `partial`, `blocked`, and completed-empty behavior. | `OWASP_2025_COVERAGE.md` |
| Manual validation guidance | Candidate records become category-specific tasks with target, evidence source, required identity or role, expected control, evidence to capture, and stop conditions. | `candidate_index.jsonl`, `MANUAL_TEST_PLAN.md` |
| Summary integration | `SUMMARY.md` links scope, OWASP, candidate, manual-plan, and existing findings artifacts. | Expanded `SUMMARY.md` |
| Safety boundary | No account creation, credential guessing, password spraying, MFA bypass, uncontrolled third-party scanning, or destructive validation by default. | Documented in README, INSTALL, ARCHITECTURE, and tasklist |

## Current pipeline order

The current dependency graph performs subdomain enumeration, then `scope_guard`, then DNS and HTTP probing. Endpoint enrichment and scanner stages run only from bounded, in-scope streams. Finalization loads stage-health records and redacted evidence before generating the OWASP coverage and manual-plan artifacts.

```text
subfinder / assetfinder / amass
    → subs.txt
    → scope_guard
    → scoped_subs.txt + scope.json + in_scope_hosts.txt + out_of_scope_hosts.txt
    → dnsx → live_subs.txt
    → httpx → alive.txt
    → crawl / history / API / JavaScript enrichment
    → bounded vulnerability and finder stages
    → evidence.jsonl + candidate_index.jsonl
    → OWASP_2025_COVERAGE.md + MANUAL_TEST_PLAN.md
    → SUMMARY.md + findings.md
```

## OWASP coverage policy

| State | Meaning |
|---|---|
| `covered` | All mapped automated stages completed or completed-empty and the required black-box input was available. This is not a security guarantee. |
| `partial` | Automation ran, but manual validation or additional context is required. This is the normal state for access control, authentication, business logic, and exceptional conditions. |
| `blocked` | A relevant stage failed, timed out, was skipped, or requires an unavailable repository, deployment, identity, workflow, or logging input. |
| `completed_empty` | A stage completed successfully with valid empty input or no candidate output. This must remain distinguishable from failure. |
| `candidate` | A scanner or finder produced a lead that has not been reproduced and impact-confirmed. |

## Future workstreams

### Identity-aware access-control validation

Add optional, operator-supplied second-session and role metadata. RFUF may generate a safe two-account comparison task automatically, but it must not create accounts or guess credentials. Validation should remain non-destructive and use synthetic objects or a local replica.

### Source and supply-chain review

Add an optional repository or manifest input for `go.mod`, Node lockfiles, Python lockfiles, container definitions, SBOMs, and CI workflows. This must be a separate input path from the public-domain scan because A03 cannot be established from URLs alone.

### Cryptographic and transport review

Add optional TLS and certificate policy checks, token-rotation checks, password-hash review, and key-management evidence. JWT and cookie heuristics remain candidate signals rather than complete cryptographic assessment.

### Logging and exceptional-condition review

Add a test-tenant workflow for verifying audit records, alerting, actor attribution, retention, and tamper resistance. Add local or test-environment cases for fail-open authorization, retries, rollback, idempotency, partial failure, and resource limits.

## Fedora runtime remediation

The pipeline now validates each recon stage against the artifact its producer actually writes. In particular, `subfinder` is checked against `subfinder.txt` and Amass against `amass_raw.txt`; an existing empty file is reported as `completed_empty` rather than `failed`.

The Fedora installer checks representative binaries instead of treating package names such as `ca-certificates` and `openssl` as PATH commands. Interactive package commands receive `os.Stdin`, while non-interactive runs report a manual-install recovery path when password-authenticated sudo is unavailable. Interactsh startup is optional, waits up to 20 seconds by default, supports `-interactsh-timeout 0`, and keeps a successfully started client alive through the scan.

## Validation requirements

Every change must pass:

```bash
gofmt -w <changed-go-files>
go test ./...
go vet ./...
go build ./cmd/rfuf
go build ./cmd/scope-filter
git diff --check
```

Local fixture tests must use synthetic hosts and URLs only. No live external target is part of repository validation.

## References

[1]: https://owasp.org/Top10/2025/en/ "OWASP Top 10:2025 official release"

[2]: https://github.com/CyberShuriken/rfuf/blob/main/ARCHITECTURE.md "RFUF architecture and pipeline stages"
