# Changelog

## v0.1.0 — ftsgw Phase 0 (2026-05-12)

### Added

- `ftsgw-server` authentication broker.
  - LDAP simple-bind authentication with paged transitive-group search.
  - Ed25519-signed JWT app-tokens, 15-minute TTL, refresh bounded at 4h from `iat`.
  - `/v1/auth/{token,refresh,logout}`, `/v1/me`, `/v1/.well-known/jwks.json`, `/healthz`, `/readyz`, `/metrics`.
  - Synchronous dual-sink audit log (SQLite `audit_events` + rotated JSON-lines).
  - Per-IP and per-username rate limiting.
  - Admin subcommands: `revoke`, `rotate-key`, `version`.
  - Prometheus metrics, OTLP tracing, structured slog with secret redaction.
- `ftsgw-cli` companion client.
  - `login`, `whoami`, `logout`, `status`, `version`.
  - Token cache at `~/.config/ftsgw/token.json` (mode 0600).
  - Auto-refresh at 80% of TTL with refresh-window-exhaustion surfacing.
  - Explicit exit codes (0/1/2/3/4/5) for shell scripting.
- Integration tests under `ftsgw/test/integration` (testcontainers OpenLDAP).
- 60-second fuzz pass against JWT validate.
- `make demo` ⇒ throwaway OpenLDAP + broker + CLI walkthrough.
- Distroless container image, OpenShift manifests.

### Not yet

- Entra / AD FS integration (Phase 1).
- mTLS, HSM-backed signing, HA (Phase 2).
