# RFUF Pipeline Reliability and Coverage Implementation Plan

**Author:** Manus AI  
**Status:** Approved for implementation in the current working branch  
**Scope:** Authorized wildcard bug-finding and reconnaissance workflows only

## Executive diagnosis

The reported run was not a single scanner failure. It was a **coverage and observability failure across the pipeline**: several stages executed against a narrow host list, the JavaScript collection stage did not discover the asset classes used by modern applications, the SQLi command used a fragile target-file mechanism, and authentication was configured only as replayed user input rather than as a session bootstrap.

The repository already contains partial fixes for API-spec discovery, JavaScript mining, TruffleHog filesystem scanning, and `-auth-cookie`/`-auth-bearer`. Those changes are not sufficient because the stages do not share one canonical, progressively enriched target stream, JavaScript collection is limited to a small HTML `src="*.js"` pattern, and the nuclei helper used by some stages does not actually inject authentication headers.

## Confirmed findings

| Finding | Evidence in current code | Impact | Planned correction |
|---|---|---|---|
| Fragile sqlmap input | `sqlmap_scan` invokes `sqlmap -m <(head -n ... sqli_targets.txt)` | Process substitution is valid in the outer Bash smoke test, but it is a poor file contract for a third-party CLI and can fail or be unreadable as `/dev/fd/*`; errors are currently easy to miss because the stage ends with `true` | Materialize a capped file such as `sqlmap_targets.txt`, invoke `sqlmap -m sqlmap_targets.txt`, capture stdout/stderr, record the exit status, and preserve partial output without masking diagnostics |
| Stale/narrow target fan-out | Exposure, misconfiguration, auth, and GraphQL nuclei stages all use `alive.txt` and depend directly on `httpx_probe` | A run with nine alive hosts scans nine hosts even after crawling, historical mining, API-spec parsing, and JavaScript extraction discover more URLs | Add a canonical target merge stage after URL/API/JS discovery, create explicit host and endpoint streams, and make each scanner declare the correct source and dependency |
| JavaScript coverage gap | `jsmap_scrape` only extracts `src="...js"` from the root HTML and caps results at 30 per host | It misses `static/js/`, `_next/static/chunks/` discovered indirectly, preload/module links, Next.js manifests, asset manifests, inline JSON, and bundle URLs already found by crawl/history | Implement authenticated, bounded asset collection from HTML, link/preload/module attributes, known manifest paths, `all_urls.txt`, and Next.js/static-js patterns; normalize relative URLs and deduplicate before download |
| Manifest files not analyzed | No manifest download or parser exists in `jsmap_scrape`; `merge_all_urls` only parses downloaded API-spec JSON | Modern SPA route and chunk manifests are absent from endpoint mining | Download manifest candidates, parse JSON conservatively for URL/path-like strings, and feed discovered assets/endpoints into the same deduplicated streams |
| TruffleHog observability gap | Each filesystem invocation redirects stderr to `/dev/null`, uses `|| true`, and the result file is sorted as opaque text | An unavailable/unsupported invocation and a clean scan both look like an empty result; users cannot distinguish “not run”, “failed”, and “no secrets” | Verify the installed CLI once, run filesystem scans with JSON output where supported, capture diagnostics in `.rfuf/trufflehog.log`, write a status file, and keep findings separate from execution errors |
| Auth session is replay-only | CLI accepts `-auth-cookie` and `-auth-bearer`; no login/session creation flow exists, and `nucleotidesOptimizedAuth()` returns plain nuclei flags | Authenticated endpoints remain invisible unless the user manually supplies a cookie/token; several stages do not receive auth at all | Preserve explicit cookie/bearer replay. Add an optional session-file/header-file input and an opt-in login bootstrap only when credentials and a target-specific flow are supplied; never auto-register accounts or attempt login with guessed credentials |
| Auth not threaded consistently | `authSnip` is used in some stages, but the nuclei helper is explicitly a placeholder and some raw curl/JS commands omit auth | Authenticated crawling, API discovery, JavaScript download, URL probing, and nuclei scans can disagree about reachability | Centralize shell header construction and use it for `curl`, `httpx`, `katana`, `nuclei`, sqlmap, and JS/manifest fetches; add tests that inspect generated commands and child environments |
| Stage outputs are weakly validated | Many stages classify empty output as successful by design, but do not emit counts or reason codes | The dashboard/checkpoint can say “complete” while scanning zero inputs | Emit per-stage input/output counts and an explicit empty-input status; retain checkpoint semantics while making zero-target conditions visible |

## Implementation sequence

### 1. Establish canonical target streams

Add a target-merge stage after crawling, historical URL mining, API-spec parsing, and JavaScript/manifest collection. It will produce stable, documented artifacts rather than making every scanner independently choose `alive.txt`.

| Artifact | Meaning | Consumers |
|---|---|---|
| `alive.txt` | Live base hosts from HTTP probing | Host-level probes, WAF, ports, CORS, directory discovery |
| `all_urls.txt` | Deduplicated URLs from crawl, history, OpenAPI, manifests, and JS | Manual review, discovery, endpoint preparation |
| `all_urls_testable.txt` | URLs accepted by the existing testability filter, including auth-walled statuses | Vulnerability target builders |
| `all_urls_200.txt` | Backward-compatible filtered stream containing 200/redirect/auth-required/method statuses | Existing downstream stages and reports |
| `js_assets.txt` | Deduplicated JavaScript, source-map, and manifest URLs | Download/mining stage |
| `js_endpoints.txt` | Normalized endpoint URLs/paths extracted from downloaded assets | Nuclei endpoint pass and Go JS miner |
| `nuclei_targets.txt` | Bounded union of live hosts plus discovered testable endpoints | Exposure, misconfiguration, auth, GraphQL, and custom template passes |

Every scanner will depend on the stage that produces its input. This prevents an early host-only stage from silently becoming the effective limit for the entire run.

### 2. Replace sqlmap process substitution with a real target file

The SQLi preparation stage will write a bounded, deduplicated `sqlmap_targets.txt`. The SQLmap stage will consume that named file with `-m sqlmap_targets.txt`, create `sqlmap_results/` before execution, and use a bounded shell timeout. Its output will include a machine-readable status record containing the target count, exit code, and whether the timeout was reached.

The existing safety limits remain: only the intended authorized target list is used, the target count is capped, and no shell expansion of user-controlled URL content is introduced.

### 3. Expand JavaScript, Next.js, and manifest collection

The collector will use bounded requests and authenticated headers to gather asset references from:

- HTML `script[src]`, `link[href]`, preload/modulepreload, and inline JSON references;
- known manifest locations such as `asset-manifest.json`, `manifest.json`, `build-manifest.json`, `routes-manifest.json`, and Next.js build manifests;
- URLs already present in `katana_urls.txt`, `all_urls.txt`, and API discovery output that match static JavaScript, source-map, or manifest patterns;
- Next.js `/_next/static/` and conventional `/static/js/` paths.

It will normalize relative, protocol-relative, and absolute URLs, enforce same-scope filtering, deduplicate, cap per-host and total asset counts, download bundles/maps/manifests, and extract endpoint-like strings without treating every arbitrary token as a URL. Manifest parsing will be tolerant of JSON nesting and will not execute downloaded content.

### 4. Make authentication explicit and consistent

The safe default remains **unauthenticated scanning**. The implementation will support the following modes:

| Mode | Behavior |
|---|---|
| No auth flags | Scan public scope only and record `auth_mode=none` |
| `-auth-cookie` | Replay the supplied cookie in every supported HTTP request |
| `-auth-bearer` | Replay the supplied bearer token in `Authorization` |
| Header/session file | Load user-supplied, local-only headers or a cookie-jar path without printing secrets |
| Optional login bootstrap | Only run when the user explicitly supplies a target-specific login URL and credentials through a protected local mechanism; no account creation, credential guessing, or automatic use of `/signup` |

Because login forms, CSRF tokens, MFA, and SSO vary by target, the plan does not invent a generic login flow that could be unsafe or unreliable. If no usable session is supplied, the run will state that authenticated coverage was not performed instead of implying that the private surface was tested.

### 5. Fix nuclei and request-header propagation

Replace the placeholder nuclei-auth helper with a shell-safe header block. Each nuclei invocation will receive `-H 'Cookie: ...'` and/or `-H 'Authorization: ...'` only when configured. The same helper will be used by API discovery, JavaScript/manifest downloads, katana, httpx, curl-based probes, and custom nuclei templates.

Secrets will not be written to command logs or status reports. The executor log will redact configured cookie and bearer values before persisting command text and child output where practical.

### 6. Make TruffleHog failures distinguishable from clean scans

The stage will first check the executable and record its version. It will then scan only existing, non-empty artifacts, using the documented `filesystem` source and JSON output when available [1]. Standard error will be retained in `.rfuf/trufflehog.log`; a separate `trufflehog_status.json` will report `not_installed`, `no_inputs`, `scan_error`, or `completed` with input counts. A clean scan will remain a valid result, but it will no longer be indistinguishable from a command failure.

### 7. Improve stage metrics and checkpoint diagnostics

For each target-producing and scanner stage, write a small status record with input path, input count, output path, output count, command status, and skip reason. Checkpoints will continue to mark bounded timeout stages as completed when partial output is intentionally preserved, but the summary will expose the timeout and partial-result state.

## Regression and integration tests

The test suite will include deterministic tests that do not contact third-party targets:

1. A generated SQLi command must contain `sqlmap_targets.txt`, never process substitution, and preserve the target cap.
2. A synthetic target graph must show nuclei exposure/auth/GraphQL stages depending on the canonical enriched target stream rather than only `alive.txt`.
3. A local HTTP fixture must expose HTML, Next.js chunks, `/static/js/`, and manifest files; the collector must discover, normalize, deduplicate, and download each expected asset.
4. A fixture manifest containing nested route strings must produce endpoint candidates while ignoring unrelated values.
5. Authenticated fixture requests must receive the configured cookie/bearer header, while logs and status files must not contain the secret value.
6. A fake TruffleHog executable must cover clean output, findings output, and non-zero execution with stderr; each state must produce a distinct status.
7. Existing pipeline, executor, findings, and summary tests must continue to pass.
8. The repository must pass `gofmt`, `go vet ./...`, `go test ./...`, and `go build ./cmd/rfuf`.

## Safety and authorization boundary

RFUF will remain a tool for assets the operator is explicitly authorized to test. The implementation will not add automatic account creation, password spraying, credential guessing, MFA bypass, or uncontrolled scanning outside the supplied wildcard scope. Authenticated testing will use only user-provided session material or explicitly configured credentials and endpoints.

## Delivery checklist

| Item | Required result |
|---|---|
| Code | Pipeline changes implemented with focused tests |
| Documentation | `README.md`, `ARCHITECTURE.md`, `INSTALL.md` if flags change, and this plan updated to match behavior |
| Validation | Build, vet, unit tests, and safe local fixtures pass |
| Git | Changes committed on the working branch and pushed to `origin/main` |
| Final report | Root causes, fixes, test results, commit ID, and pushed branch reported to the user |

## References

[1]: https://github.com/trufflesecurity/trufflehog "TruffleHog official repository and filesystem scanning documentation"

## Implementation completed

The plan has been implemented in the current branch. The delivered changes include a materialized `sqlmap_targets.txt` contract with `sqlmap_status.json`, enriched `nuclei_targets.txt` fan-out, modern JavaScript and manifest collection with bounded authenticated downloads, explicit cookie/bearer file inputs, `-auth-required`, array-safe request arguments, and observable TruffleHog status and diagnostics.

The local integration fixture verified discovery of Next.js chunks, conventional `/static/js/` assets, manifests, and API endpoints while replaying a session cookie. The repository validation completed successfully with `go test ./...`, `go vet ./...`, `go build ./cmd/rfuf`, and `git diff --check`.

The implementation intentionally does not create accounts, submit signup forms, guess credentials, bypass MFA, or scan live external targets as part of validation. Authenticated coverage requires a session supplied by the authorized operator.
