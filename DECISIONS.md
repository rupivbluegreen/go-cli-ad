# Decisions

Architecture decision records for ftsgw Phase 0. New entries: append at the
bottom; never edit history without an explicit "Superseded by ADR-N" note.

## ADR-001 — Ed25519 over RS256

- **Decision:** All app-tokens are signed with Ed25519 via `jwx/v2` (`alg: EdDSA`).
- **Why:** Smaller signatures (~64B vs ~256B for RS256), constant-time signing, no padding/oracle surface area, native Go support. Phase 0 is a fresh deployment with no compatibility surface — no reason to ship RSA.
- **Trade-off:** A handful of legacy JWT verifiers don't speak EdDSA; we own both ends today, so not a concern.

## ADR-002 — No bootstrap token, no enrollment

- **Decision:** The CLI's only initial input is the user's AD password.
- **Why:** Adding a bootstrap secret means inventing a secrets-distribution process and shipping a device-identity story prematurely. Both deferred to Phase 2.
- **Trade-off:** The first login latency includes a real LDAP bind; that is fine.

## ADR-003 — Refresh window bounded at 4h from `iat`

- **Decision:** Refresh is allowed only while `now - iat <= 4h`. `iat` is preserved across refreshes.
- **Why:** Without a hard ceiling, the chain extends indefinitely; one stolen token equals permanent access. Four hours matches typical bank session policy and bounds blast radius without forcing a re-prompt every 15 minutes.
- **Test:** `auth.TestRefreshOutsideWindowRefused`.

## ADR-004 — SQLite over Postgres

- **Decision:** `revoked_tokens` and `audit_events` live in a single SQLite database with WAL.
- **Why:** Phase 0 is single-node by design; SQLite removes a stateful dependency from the deployment. modernc.org/sqlite is pure Go (no cgo). Moving to Postgres later is a `database/sql` driver swap plus a migration replay.

## ADR-005 — Synchronous audit writes

- **Decision:** Audit writes fail the request (HTTP 503) if either sink errors.
- **Why:** Bank audit standards require that a successful response implies a recorded event. Async writes can drop on crash.
- **Trade-off:** Audit-sink unavailability halts new auths — operators must monitor `ftsgw_audit_write_failures_total`.

## ADR-006 — Distroless static-debian12:nonroot

- **Decision:** Runtime image is `gcr.io/distroless/static-debian12:nonroot`.
- **Why:** No shell, no package manager, no userland — minimal attack surface. Matches the bank's preferred runtime.
- **Trade-off:** Debugging requires `kubectl debug` with a `--target` ephemeral container.

## ADR-007 — Single Go module, ftsgw under `/ftsgw` subtree

- **Decision:** ftsgw lives under `/ftsgw/...` in the existing `github.com/rupivbluegreen/go-cli-ad` module.
- **Why:** Reuses tooling (CI, vendor tree, golangci-lint config) and keeps the two products visible side-by-side. No second `go.mod` to maintain.
- **Trade-off:** Imports are slightly longer (`.../ftsgw/internal/server/...`).

## ADR-008 — chi over net/http mux

- **Decision:** HTTP routing via `github.com/go-chi/chi/v5`.
- **Why:** Sub-router composition, middleware chaining, and clean route table fit the broker's surface area. Std mux is too thin for our middleware order (request-id, recover, access log, rate limit) without ad-hoc wrappers.

## ADR-009 — jwx/v2 over golang-jwt

- **Decision:** JWT minting and parsing via `github.com/lestrrat-go/jwx/v2`.
- **Why:** Better ergonomics for Ed25519 + JWKS publication; clean separation between `jws`, `jwk`, `jwt` packages; active maintenance.

## ADR-010 — modernc.org/sqlite over mattn/go-sqlite3

- **Decision:** Pure-Go SQLite driver.
- **Why:** Constraint says `CGO_ENABLED=0` everywhere. mattn requires cgo.
- **Trade-off:** Slightly slower than cgo; not measurable at our write rate.

## ADR-011 — IdP interface includes challenge methods today

- **Decision:** `InitiateChallenge` / `CompleteChallenge` live on `IdentityProvider` in Phase 0 even though LDAP returns `ErrNotSupported`.
- **Why:** Adding methods to an interface in Phase 1 means recompiling every implementer. Defining them now means Phase 1 = drop in an `EntraProvider` implementation, nothing else.

## ADR-012 — Clock is an interface

- **Decision:** Auth code reads time only via `Clock.Now()`.
- **Why:** Refresh-window exhaustion tests would otherwise sleep four hours. Production code uses `RealClock{}`; tests use `fakeClock`. No production code changes when adding tests.

## ADR-013 — Demo uses LDAP (no TLS) and a self-signed broker cert

- **Decision:** `scripts/ftsgw-demo.sh` runs OpenLDAP without TLS and a one-day self-signed broker cert.
- **Why:** Demo is local-only, ephemeral, and runs as the developer; no real secrets cross the wire. Production config in `deploy/ftsgw/openshift/configmap.yaml` is LDAPS-only with `start_tls: false` (because the broker uses `ldaps://`) and trusts the org CA bundle.

## ADR-014 — Cosign signing is operator-driven

- **Decision:** Makefile target `ftsgw-sign` exists but is not run by CI in Phase 0.
- **Why:** Signing requires the bank's cosign key, which is not available in this repo's CI. Operators run `COSIGN_KEY=… make ftsgw-sign` post-release.
