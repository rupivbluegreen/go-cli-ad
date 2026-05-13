# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repo holds two products in one Go module

`github.com/rupivbluegreen/go-cli-ad` (ADR-007) contains:

- **go-cli-ad** — CLI + Bubble Tea TUI that reads group/role memberships from on-prem AD (LDAP) or Entra (device code). Sources: `cmd/go-cli-ad/`, `internal/{cli,tui,config,onprem,azure,output}/`.
- **ftsgw** — auth broker (`ftsgw-server`) and its companion CLI (`ftsgw-cli`). Everything ftsgw-related lives under `ftsgw/` and `deploy/ftsgw/` and `docs/ftsgw/`. The two products share nothing at runtime; do not cross-import.

Vendor tree (`vendor/`) is checked in. `go` picks vendor mode automatically because the tree exists and `go.mod` is current; `make ftsgw-vendor` (`go mod tidy && go mod vendor`) refreshes it after dep changes.

## Commands

```sh
# go-cli-ad
go build -o bin/go-cli-ad ./cmd/go-cli-ad

# ftsgw
make ftsgw-build              # builds ftsgw-server + ftsgw-cli into bin/
make ftsgw-test               # unit tests, -race -count=1
make ftsgw-test-integration   # testcontainers OpenLDAP; needs Docker
make ftsgw-lint               # golangci-lint + license-header check
make ftsgw-vet
make ftsgw-vendor             # go mod tidy && go mod vendor
make ftsgw-demo               # OpenLDAP container + broker + CLI walkthrough
make ftsgw-image              # distroless container build

# whole repo (CI also runs these)
go test ./...
go vet ./...
golangci-lint run --timeout=5m

# single test / subtest
go test -run TestRefreshOutsideWindowRefused ./ftsgw/internal/server/auth
go test -run TestX/subtest_name ./ftsgw/...

# fuzz the JWT validator (corpus already in auth/fuzz_test.go)
go test -fuzz=FuzzValidate -fuzztime=60s ./ftsgw/internal/server/auth
```

CI matrix (`.github/workflows/ci.yml`) runs on ubuntu/macos/windows; `go mod tidy` cleanliness is enforced on non-Windows. Releases (`v*` tag) build cross-platform binaries for go-cli-ad only.

## ftsgw architecture (the part that needs reading multiple files)

The broker is a single chi-router HTTP service that wraps an `IdentityProvider` behind JWT issuance:

```
ftsgw/internal/server/
  api/        chi router, handlers, middleware (request-id → recover → access log → rate limit), problem-details
  auth/       token mint/verify (Ed25519 via jwx/v2), Clock interface, refresh window
  idp/        IdentityProvider seam — LDAPProvider (Phase 0) and EntraProvider (Phase 1, in progress)
  signer/     key material + JWKS publication
  store/      modernc.org/sqlite (no cgo) — revoked_tokens, audit_events, pending_challenges
              migrations/000N_*.sql apply in numeric order; add a new file, never edit a shipped one
  audit/      dual sink: SQLite + rotated JSON-lines (lumberjack), synchronous
  config/     YAML config loader
  obs/        Prometheus metrics, OTLP traces, slog with secret redaction
```

Load-bearing design rules — break these and tests/security guarantees collapse:

- **Never add methods to `idp.IdentityProvider`.** The interface already includes `InitiateChallenge` / `CompleteChallenge` / `Capabilities` precisely so Phase 1 Entra can ship without touching every implementer (ADR-011). LDAPProvider returns `ErrNotSupported` for the challenge methods.
- **Auth code reads time only via `Clock.Now()`** (ADR-012). Production: `RealClock{}`. Tests: `fakeClock`. Don't reach for `time.Now()` directly in `auth/` or refresh-window tests will lie.
- **Refresh window is `now - iat <= 4h`, and `iat` is preserved across refreshes** (ADR-003). Covered by `auth.TestRefreshOutsideWindowRefused`.
- **Audit writes are synchronous and fail the request (HTTP 503) if either sink errors** (ADR-005). A successful response means an event was recorded. Don't introduce buffered/async audit paths.
- **`CGO_ENABLED=0` everywhere** (ADR-010 + Makefile). Use `modernc.org/sqlite`, not `mattn/go-sqlite3`. Don't add cgo deps.
- **Tokens are Ed25519 (`alg: EdDSA`) via `jwx/v2`** (ADR-001/009). Don't reintroduce RS256.
- **Routing is `github.com/go-chi/chi/v5`** (ADR-008), not net/http mux.

Architectural choices live in `DECISIONS.md` as numbered ADRs — append new ones at the bottom; mark superseded entries with "Superseded by ADR-N" rather than rewriting history. Phase 1 seams are documented in `PHASE_1_NOTES.md`.

## go-cli-ad architecture

`internal/cli/root.go` auto-launches the Bubble Tea TUI when invoked with no args on a TTY; in non-TTY contexts the same binary prints help (so scripts that piped to it before still work). Token cache at `~/.config/go-cli-ad/azure-token.json` (mode 0600). Nested AD groups use matching rule `1.2.840.113556.1.4.1941`.

Exit codes are part of the contract (see README "Exit codes" table): 1=auth, 2=network, 3=device-code/expired, 4=config, 5=post-auth query.

## Conventions worth knowing

- **Every `.go` file under `ftsgw/` must start with the Apache 2.0 header** in `ftsgw/LICENSE_HEADER.txt`. Enforced by `scripts/check-license-headers.sh` (runs in `make ftsgw-lint`). When creating new files in `ftsgw/`, copy the header from a neighboring file.
- **golangci-lint config** (`.golangci.yml`) enables only `errcheck`, `govet`, `ineffassign`, `staticcheck`, `unused`. `fmt.Fprint*` is excluded from errcheck — everything else must handle returned errors. The lint job runs on Ubuntu only; Windows-specific paths skip the `go mod tidy` check.
- **No new top-level docs unless asked.** The repo intentionally keeps a small set: `README.md`, `CHANGELOG.md`, `DECISIONS.md`, `PHASE_1_NOTES.md`, and `docs/ftsgw/*.md`. Architecture rationale belongs in a new ADR in `DECISIONS.md`, not a fresh markdown file.
- **Demo config** (`scripts/ftsgw-demo-config.yaml.tpl`, `scripts/ftsgw-demo-seed.ldif`) intentionally runs without LDAPS and uses a self-signed broker cert (ADR-013). Don't "fix" it to mirror production — production config lives in `deploy/ftsgw/openshift/`.
