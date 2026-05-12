# ftsgw Phase 1 Implementation Plan

> **For agentic workers:** This plan extends `2026-05-12-ftsgw-phase-0.md`. Patterns (TDD, dispatch style, commit messages, license headers, vendor tree) are inherited. Use `superpowers:subagent-driven-development` to execute. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Mode 1 (Entra-native) support to `ftsgw-server` and `ftsgw-cli`. Users authenticate via Microsoft Identity Platform device-code flow against the org's Entra tenant; groups are fetched from Microsoft Graph. LDAP path (Phase 0) remains the default and is unchanged.

**Architecture:** All seams already exist from Phase 0:
- `IdentityProvider.InitiateChallenge` / `CompleteChallenge` — currently `ErrNotSupported` on LDAP; will be implemented on a new `EntraProvider`.
- `ProviderCapabilities.SupportsChallenge` — already in the type.
- `auth.AuthMethodChallenge` — already in the enum.
- `audit.EventPasswordAuthenticated` — Phase 1 adds `EventChallengeInitiated`, `EventChallengeCompleted`.
- New SQLite table `pending_challenges` (migration `0002_pending_challenges.sql`).
- New HTTP shape: `POST /v1/auth/token` may return **202 Accepted** with a `ChallengeResponse` body when the configured IdP is challenge-based; clients poll **`POST /v1/auth/token/complete`** with `{challenge_id}` until they get a 200 `TokenResponse` or a terminal 4xx.

The token model itself (Ed25519, 15-min TTL, 4h refresh window from `iat`) is unchanged — `iat` records original *completed-challenge* time, just as it records original password auth time in Phase 0.

**Tech stack additions:** `github.com/Azure/azure-sdk-for-go/sdk/azidentity` (device-code credential — already in go.mod from go-cli-ad), `github.com/microsoftgraph/msgraph-sdk-go` (groups query — already in go.mod). Reuse, don't re-import.

**Decisions to record in DECISIONS.md (ADR-015 onward):**
- ADR-015 — Device-code flow over web redirect: airgapped CLI has no browser to redirect; device-code is the only viable interactive flow.
- ADR-016 — Challenge state in SQLite, not in-memory: surviving broker restart matters because device-code polls may span minutes.
- ADR-017 — Reuse `azidentity` from existing `internal/azure`: same module already vendors it; no new dep churn.
- ADR-018 — Single `/v1/auth/token` endpoint with status-based dispatch (202 vs 200) over a separate `/v1/auth/device-code` endpoint: keeps client and audit surface uniform.

---

## File map (everything new or modified)

```
ftsgw/
  pkg/api/types/
    types.go                                  MODIFY: add ChallengeResponse, CompleteChallengeRequest
  internal/server/
    store/
      migrations/0002_pending_challenges.sql  NEW
      challenges.go                           NEW: Create, Get, Delete, PruneExpired
    audit/
      events.go                               MODIFY: add EventChallengeInitiated, EventChallengeCompleted
    idp/
      entra.go                                NEW: full EntraProvider implementation (replaces entra_stub.go)
      entra_stub.go                           DELETE
      entra_test.go                           NEW: unit tests with fakes
    config/
      config.go                               MODIFY: add EntraConfig (tenant_id, client_id, scopes)
    api/
      handlers_auth.go                        MODIFY: HandleTokenIssue returns 202 if SupportsChallenge
      handlers_complete.go                    NEW: POST /v1/auth/token/complete
      router.go                               MODIFY: add /v1/auth/token/complete route
  cmd/ftsgw-server/
    main.go                                   MODIFY: buildProvider branches on "entra"
  internal/cli/
    client.go                                 MODIFY: Login handles 202, polls Complete
    login.go                                  MODIFY: prints device code prompt to stderr
docs/ftsgw/
  auth-flow.md                                MODIFY: add Entra device-code mermaid sequence
  threat-model.md                             MODIFY: new STRIDE items for token in Entra cache, etc.
  deployment.md                               MODIFY: Mode 1 config example
DECISIONS.md                                  APPEND: ADR-015..018
CHANGELOG.md                                  APPEND: v0.2.0
PHASE_2_NOTES.md                              NEW: mTLS + HSM + HA notes
README.md                                     MODIFY: mention Mode 1
```

---

## Phase ordering

Each phase produces a green commit. Dispatch one implementer subagent per phase. Most phases match the granularity used in Phase 0; the Entra implementation itself (Phase 1.4) is the meaty one.

1. **Phase 1.1 — Shared API types**: `ChallengeResponse`, `CompleteChallengeRequest`. Pure data types + roundtrip test.
2. **Phase 1.2 — Audit event constants**: extend the `EventType` enum.
3. **Phase 1.3 — Pending-challenges table**: migration + `Store.CreateChallenge`/`GetChallenge`/`DeleteChallenge`/`PruneExpiredChallenges` + tests.
4. **Phase 1.4 — `EntraProvider`** (biggest task): wire azidentity device-code credential, store the in-flight `DeviceAuthorizationResponse`, implement `InitiateChallenge` / `CompleteChallenge` to poll the credential and resolve groups via msgraph-sdk-go. Unit tests with a mocked credential and graph client. The `entra_stub.go` is deleted in this commit.
5. **Phase 1.5 — `EntraConfig` and config wiring**: add `tenant_id`, `client_id`, optional `scopes` to YAML; `applyDefaults` fills `scopes` with `["https://graph.microsoft.com/.default"]` and `client_id` with the well-known Azure CLI ID (`04b07795-8ddb-461a-bbee-02f9e1bf7b46`); validation rejects empty `tenant_id`.
6. **Phase 1.6 — Token-issue handler**: when `d.IdP.Capabilities().SupportsChallenge`, branch — call `InitiateChallenge`, persist the row, return 202 + `ChallengeResponse`. Password handlers remain when `SupportsPassword`. If both are true, prefer the request shape (presence of `username` and `password` in body → password; absent body or `Accept: application/vnd.ftsgw.challenge` → challenge).
7. **Phase 1.7 — Complete handler**: `POST /v1/auth/token/complete` body `{challenge_id}`. Looks up the row, calls `CompleteChallenge(ctx, id)`, on success mints a token (`auth_method=challenge`), audits `EventChallengeCompleted`, deletes the row, returns 200 `TokenResponse`. On `still_pending` returns 202 again. On terminal errors (expired, denied) returns 4xx with `ProblemDetails`.
8. **Phase 1.8 — Pruner extension**: server main's existing 5-min pruner gains `PruneExpiredChallenges`.
9. **Phase 1.9 — CLI changes**: `Client.Login` becomes `LoginPassword(...)` (renamed for clarity) and a new `LoginChallenge()` method handles 202 → print prompt → poll. `cmd login` decides based on broker capability hint or `--challenge` flag; default behavior is to attempt password and fall back to challenge if 202 returns. Print device code + verification URL to stderr; final token-write same as Phase 0.
10. **Phase 1.10 — Server main wiring**: `buildProvider` recognizes `"entra"` and constructs `EntraProvider` from `cfg.IdP.Entra`. Update the existing stub-error path.
11. **Phase 1.11 — Integration test**: in-process e2e with a fake credential that immediately succeeds on the second poll. Exercises 200-only path AND 202-then-200 path through the actual broker via `httptest.Server` + `Client.LoginChallenge`.
12. **Phase 1.12 — Docs**: append to `auth-flow.md` (Entra mermaid), `threat-model.md`, `deployment.md`; ADR additions in `DECISIONS.md`; `CHANGELOG.md` v0.2.0; refresh `PHASE_1_NOTES.md` to be retrospective; create `PHASE_2_NOTES.md`; update `README.md`.

---

## Notes for implementers

**Vendor tree:** Phase 1 will add no new direct dependencies if we strictly reuse `azidentity` and `msgraph-sdk-go` from the existing module. If we touch anything new, re-run `go mod vendor` and commit a vendor delta in the same commit that introduces the import.

**Audit on password vs challenge:** the existing `audit.Event` already carries `auth_method`; add only the new event types in §1.2. Reuse `EventTokenIssued` for the final mint event — its `auth_method` extra distinguishes the two flows.

**Token model unchanged:** `iat = clock.Now()` when the challenge completes. Tests for refresh-window behavior carry over without modification (just use `auth.AuthMethodChallenge` in the Subject when minting).

**Graph groups query:** use `client.Me().TransitiveMemberOf().Get(...)`. The pattern already exists in `internal/azure/graph.go` — copy idioms, not code, into the new `EntraProvider.lookupGroups`.

**Race-safe challenge cleanup:** `CompleteChallenge` must be idempotent within a single challenge ID; two concurrent polls from the CLI shouldn't double-mint a token. Use a `INSERT OR IGNORE` revocation row keyed on `challenge_id` or guard with a transactional `UPDATE … WHERE state='pending'` returning a row count.

**HTTP 202 contract:** `Retry-After` header should be set to the polling interval recommended by the credential (typically 5 s). The CLI honors it.

---

## Verification (after every phase)

- [ ] `go test -race -count=1 ./ftsgw/...` clean
- [ ] `bash scripts/check-license-headers.sh` clean
- [ ] `make ftsgw-build` produces both binaries
- [ ] License headers on every new `.go` file
- [ ] Single commit per phase with descriptive message

**Phase complete signal:** all 12 phases land + integration test in §1.11 passes locally → tag `v0.2.0` after merge.

---

## Open questions to resolve before Phase 1.4

1. Does the bank ship a custom Azure CLI registration, or do we use the public CLI client ID? (Affects `applyDefaults`.)
2. Mode-1 broker is the only realistic Entra connection point in this design; do we expose `tenant_id` per request or fix it at startup? (Plan assumes startup.)
3. Should the CLI's `--challenge` flag override password fallback? (Plan assumes yes.)

Document answers in `DECISIONS.md` ADR-019 onward as they land.
