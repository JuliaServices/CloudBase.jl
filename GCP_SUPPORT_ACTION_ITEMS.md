# Action Items: CloudBase GCP Support

## Context
- Repo: CloudBase
- Worktree: /Users/jacob.quinn/.julia/dev/CloudBase
- Branch: main

## Items

### [x] ITEM-001 (P0) Add `CloudBase.GCP` module skeleton, docs correction, and explicit bearer-token support
- Description: `CloudBase` documentation currently claims GCP support exists, but `main` only implements AWS and Azure. Add the provider skeleton, wire it into the package, expose the same HTTP client surface area as the existing providers, and support explicit access-token based auth so the new module is immediately usable and testable.
- Desired outcome: Users can call `CloudBase.GCP.get/put/post/delete/head/request/open` with an explicit bearer token, unauthenticated public requests still work, package docs no longer overstate current behavior, and the repo has a stable base for richer GCP credential flows.
- Affected files: `src/CloudBase.jl`, `src/gcp.jl`, `README.md`, `docs/src/index.md`, `test/runtests.jl`
- Implementation notes:
  - Add `include("gcp.jl")` and a `CloudBase.GCP` submodule matching the existing AWS/Azure client ergonomics.
  - Introduce the initial `GCPCredentials` type and explicit access-token constructor with redacted `show`.
  - Implement request signing/header injection for bearer tokens and preserve public-request behavior when no credentials are provided.
  - Update top-level docs to describe shipped vs. in-progress GCP support accurately.
  - Add baseline request-level tests for header injection and credential redaction.
- Verification:
  - `julia --project=. --startup-file=no -e 'using Pkg; Pkg.test()'`
- Assumptions:
  - The initial GCP client should mirror the AWS/Azure user-facing method names even if the internals differ.
  - Bearer-token auth is the safest initial auth mode because it works across Google APIs and Cloud Storage.
- Risks:
  - Over-designing the credential model too early could make later ADC flows harder to implement cleanly.
- Completion criteria:
  - `CloudBase.GCP` loads successfully from `main`.
  - Explicit access-token requests are covered by tests.
  - Package/docs accurately describe the current state after the new module lands.
- Verification evidence:
  - `2026-03-06`: `julia --project=. --startup-file=no -e 'using Pkg; Pkg.test()'` passed after adding `src/gcp.jl`, request tests, redaction coverage, and doc updates.

### [x] ITEM-002 (P0) Implement service-account and metadata-server bearer credential flows
- Description: Production GCP workloads need first-class non-interactive auth. Add service-account JSON support with JWT bearer exchange, metadata-server access token refresh, expiration handling, and ADC discovery for these flows.
- Desired outcome: `GCP.Credentials()` can discover `GOOGLE_APPLICATION_CREDENTIALS` service-account files and metadata-server credentials, refresh tokens automatically before expiry, and safely reuse credentials across concurrent requests.
- Affected files: `src/gcp.jl`, `src/CloudBase.jl`, `src/CloudTest.jl`, `test/runtests.jl`, `Project.toml`, `Manifest.toml`
- Implementation notes:
  - Add the internal credential-source model needed to distinguish static access tokens from refreshable sources.
  - Implement service-account JWT assertion generation and token exchange against `token_uri`.
  - Implement metadata-server token loading with required request headers and expiry parsing.
  - Wire refresh behavior through the existing `expireThreshold` pattern under locking.
  - Extend `CloudTest` with mock token and metadata helpers so the tests stay hermetic.
- Verification:
  - `julia --project=. --startup-file=no -e 'using Pkg; Pkg.test()'`
- Assumptions:
  - Adding `OpenSSL.jl` as a focused crypto dependency for RS256 signing is acceptable for this item.
  - Mock token and metadata servers are sufficient to validate CloudBase’s auth behavior without a live GCP dependency.
  - Adding `JSON.jl` as a direct dependency is acceptable so credential files and JWT/token payloads can be encoded/decoded robustly.
- Risks:
  - Service-account JWT generation has edge cases around base64url encoding, clock skew, and PEM parsing.
  - Metadata refresh logic can become flaky if expiry handling is off by even a small amount.
- Completion criteria:
  - Service-account and metadata-backed credentials refresh locally in tests.
  - Concurrency/refresh coverage exists and passes reliably.
- Verification evidence:
  - `2026-03-07`: `julia --project=. --startup-file=no -e 'using Pkg; Pkg.resolve()'` updated the manifest for direct `JSON`/`OpenSSL` deps.
  - `2026-03-07`: `julia --project=. --startup-file=no -e 'using Pkg; Pkg.test()'` passed with new service-account, metadata, JWT-shape, RS256 verification, and refresh-concurrency coverage.

### [x] ITEM-003 (P1) Implement full ADC file support for `authorized_user` and `external_account`
- Description: To make `GCP.Credentials()` feel like real ADC instead of a partial implementation, support the remaining common credential file types used by local development and keyless CI.
- Desired outcome: Well-known/local ADC files can back `authorized_user` refresh-token auth and `external_account` / workload-identity-federation token exchange, with clear errors for unsupported or malformed configs.
- Affected files: `src/gcp.jl`, `src/CloudTest.jl`, `test/runtests.jl`, `README.md`, `docs/src/index.md`
- Implementation notes:
  - Implement authorized-user refresh-token exchange against Google OAuth token endpoints.
  - Implement external-account config parsing and STS exchange for workload identity federation.
  - Keep discovery order and refresh semantics aligned with ADC expectations.
  - Add local mock servers for token exchange and subject-token acquisition where feasible.
  - Document exactly which ADC flows are supported.
- Verification:
  - `julia --project=. --startup-file=no -e 'using Pkg; Pkg.test()'`
- Assumptions:
  - We can model external-account coverage with local mock HTTP endpoints instead of requiring real cloud identity providers in default tests.
  - Error messages should prefer clarity over trying to silently degrade unsupported configs.
  - This item will prioritize well-known `authorized_user` ADC files plus file/url-sourced `external_account` configs with STS and optional service-account impersonation, which covers the main local-dev and keyless-CI paths.
- Risks:
  - External-account configs have the most protocol surface area and are the likeliest source of subtle bugs.
- Completion criteria:
  - `GCP.Credentials()` supports the major ADC file types documented by Google.
  - Tests cover success and failure cases for authorized-user and external-account configs.
- Verification evidence:
  - `2026-03-07`: `julia --project=. --startup-file=no -e 'using Pkg; Pkg.test()'` passed with coverage for well-known `authorized_user` ADC files, file-sourced `external_account` configs with STS + impersonation, and url-sourced `external_account` configs.

### [ ] ITEM-004 (P1) Add Cloud Storage bucket primitives and HMAC/XML request signing
- Description: CloudStore will eventually need first-class GCS support. Add the CloudBase pieces that make that practical: a GCP bucket abstraction and explicit Cloud Storage XML HMAC signing/interoperability support.
- Desired outcome: `CloudBase.GCP.Bucket` exists, Cloud Storage XML requests can be authenticated with HMAC credentials, and the implementation supports the migration-oriented interop path without compromising the default bearer-token path.
- Affected files: `src/gcp.jl`, `src/CloudBase.jl`, `test/runtests.jl`, `README.md`, `docs/src/index.md`
- Implementation notes:
  - Add `GCP.Bucket <: AbstractStore` with a path-style `storage.googleapis.com/<bucket>/` base URL suitable for downstream storage work.
  - Introduce explicit HMAC credential handling distinct from bearer-token credentials.
  - Implement Cloud Storage V4 signing/canonicalization for XML API requests.
  - Add deterministic signature/canonicalization tests and request-level HMAC tests.
  - Document that HMAC support is storage-specific and intentionally opt-in.
- Verification:
  - `julia --project=. --startup-file=no -e 'using Pkg; Pkg.test()'`
- Assumptions:
  - HMAC support should be explicit and not silently selected for generic Google API requests.
  - `GCP.Bucket` belongs in CloudBase because the existing provider store types already live there.
- Risks:
  - Canonicalization bugs can be hard to spot without thorough fixture coverage.
  - Mixing bearer and HMAC paths in one module can create confusing behavior if not documented precisely.
- Completion criteria:
  - GCS bucket primitives and HMAC signing are implemented and tested.
  - The intended downstream path into CloudStore is materially unblocked.

### [ ] ITEM-005 (P1) Add live GCP smoke-test harness and finish documentation/polish
- Description: Mock-heavy tests should be the default, but we also want an opt-in way to validate a real credential against live GCP. Finish the documentation and add a small, env-gated live harness without making CI depend on it.
- Desired outcome: Contributors can run a focused live GCP smoke test when credentials are available, the default test suite remains hermetic, and the docs clearly explain supported auth modes, environment variables, and test entrypoints.
- Affected files: `test/runtests.jl`, `README.md`, `docs/src/index.md`, `docs/src/reference.md`, `.github/workflows/ci.yml`
- Implementation notes:
  - Add a narrow live smoke test gated by explicit environment variables and skipped by default.
  - Document required environment variables and expected permissions.
  - Keep CI on hermetic tests by default; only wire live tests if there is a safe, non-secret mechanism to run them.
  - Perform a final pass on examples, docs wording, and package metadata after the feature work lands.
- Verification:
  - `julia --project=. --startup-file=no -e 'using Pkg; Pkg.test()'`
  - `CLOUDBASE_RUN_GCP_LIVE_TESTS=1 julia --project=. --startup-file=no -e 'using Pkg; Pkg.test()'`
- Assumptions:
  - The live smoke test should be intentionally tiny and focused on auth + one or two real requests.
  - Default CI should remain secretless and reliable.
- Risks:
  - Live test documentation can drift if the env contract is not kept small and explicit.
- Completion criteria:
  - Default tests remain local/mock-based.
  - There is a documented opt-in live harness for validating real credentials.
  - Docs are consistent with the final shipped behavior.

## Continuity

```text
* Take investigation/review findings and make a detailed, prioritized action item .md file; ensure each action item has enough detail (description, affected files, etc.) that a fresh context/engineer "taking on" the item would understand what needs to be done and where to go to get started and ideally how to verify that it's done
* Start working on the action-item list, for each item:
  * Thoroughly investigate the action item and work involved, state assumptions, do the work, including verification step
  * Work until verification succeeds (i.e. tests pass)
  * Mark the item done in the action item list
  * Commit the work involved for this action item
  * Continue with the same steps on the next action item
* When compacting, the itemizer instructions should be preserved *exactly* to ensure continuity
* The action-item document should very clearly state the repo/worktree where the work should be done
* Post-compaction, if there are unstaged edits in files relating to the current action item, you should assume they were your own edits and should continue directly w/ work without pausing to confirm
* No shortcuts or cutting corners while doing the action item work; each item should be done thoughtfully, carefully, with production-quality effort/work put into it; we're not trying to rush the work here at all and prefer quality, robustness, and thoroughness over "quick wins".
* No backwards compat or unnecessary shims should be included unless specifically requested
```
