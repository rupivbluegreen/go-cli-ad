# ftsgw Threat Model (Phase 0, Mode 3)

Frame: airgapped VM running `ftsgw-cli` talks to `ftsgw-server` over TLS.
Server talks to AD/LDAP over LDAPS or LDAP+StartTLS. No internet egress.

## In scope
- Confidentiality and integrity of AD passwords in transit.
- Confidentiality and integrity of ftsgw app-tokens.
- Integrity of the audit log.
- Availability of the broker against credential-stuffing.

## Out of scope (deferred or owned elsewhere)
- mTLS between CLI and broker (Phase 2).
- HSM-backed signing key (Phase 2 — interface is in place).
- Compromise of the host operating system underneath the broker (treated as
  total compromise; mitigations are infra-level: SELinux, MAC, image
  attestation, host integrity).

## STRIDE

### S — Spoofing
- **Threat:** Attacker MITMs CLI→broker, harvests password.
  - **Mitigation:** Broker requires TLS 1.2+; CLI pins to the configured CA bundle. No `InsecureSkipVerify`. Add mTLS in Phase 2.
- **Threat:** Attacker steals an app-token (laptop theft, malicious process).
  - **Mitigation:** Tokens are bearer; mitigations are short TTL (15m), bounded refresh window (4h from `iat`), file mode 0600, and per-token revocation via logout. Phase 2 will bind tokens to client identity.

### T — Tampering
- **Threat:** Attacker forges a token.
  - **Mitigation:** Ed25519 signatures; verification via embedded public key (broker re-uses the same key the JWKS endpoint publishes). All validation is signature-first.
- **Threat:** Attacker writes to the audit log to hide actions.
  - **Mitigation:** Audit goes to two sinks (SQLite + JSON-lines file). Process runs as non-root with read-only root FS; only `/var/log/ftsgw-server` is writable. Forward to immutable log store (Splunk/ELK) by tailing the file.

### R — Repudiation
- **Threat:** User denies authenticating.
  - **Mitigation:** `password_authenticated`, `token_issued`, `token_refreshed`, and `token_revoked` events all carry `actor_upn`, `request_id`, `client_ip`, and `jti`. Synchronous write means an HTTP 200 implies an audit row exists.

### I — Information disclosure
- **Threat:** Password or token leaks to logs / error messages.
  - **Mitigation:** Audit `Logger.Write` enforces a deny-list on `extras` keys (`password`, `access_token`, `token`, …) and would-be-leaks fail closed. `obs.RedactingHandler` does the same for slog. Test `redaction_test.go` enforces both.
- **Threat:** JWKS exposes more than the verification key.
  - **Mitigation:** `/v1/.well-known/jwks.json` returns only `{kty:OKP, crv:Ed25519, kid, x, alg:EdDSA, use:sig}`. No private bytes ever serialized.

### D — Denial of service
- **Threat:** Credential stuffing against `/v1/auth/token`.
  - **Mitigation:** 3 attempts per username per minute, plus per-IP token bucket (5 rps, burst 10). Both fire `ftsgw_rate_limited_total` and audit `rate_limited`.
- **Threat:** SQLite contention.
  - **Mitigation:** WAL mode; per-row writes; one process. Phase 0 is single-node by design.

### E — Elevation of privilege
- **Threat:** Refresh-chain extension allowing perpetual access from a single password auth.
  - **Mitigation:** `iat` is preserved across refreshes; `now - iat > refresh_window` refuses. Tested in `TestRefreshOutsideWindowRefused`.
- **Threat:** Replay of a token after logout.
  - **Mitigation:** Logout inserts `jti` into `revoked_tokens`; every validate consults the table. Tested in `TestRevokedTokenFailsValidate` and `TestE2ELogoutInvalidatesToken`.

## Residual risks (accepted for Phase 0)

- Bearer tokens are unbound to client; theft + replay within TTL is possible.
- Single-node failure mode: broker downtime = no new logins. Acceptable for Phase 0 dev demo; HA is Phase 2.
- Audit log file is rotated on disk but not yet shipped to a tamper-evident store; operators are expected to ship the JSON-lines file off-host.
