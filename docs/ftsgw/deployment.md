# ftsgw Deployment Guide

## Required artifacts

- `bin/ftsgw-server` (or container image).
- TLS certificate + key for the HTTPS listener.
- Ed25519 signing key (PEM, mode 0600).
- LDAP service-account credentials (DN + password) supplied via env vars.

## Config

The broker reads a single YAML file (`--config`, default
`/etc/ftsgw-server/config.yaml`). See `deploy/ftsgw/openshift/configmap.yaml`
for a production example. Secret fields are referenced by env var name:

| YAML field                 | env var                       |
|----------------------------|-------------------------------|
| `idp.bind_dn_env`          | resolves to actual bind DN    |
| `idp.bind_password_env`    | resolves to bind password     |

Validation is strict at startup; the broker refuses to start when:
- any required field is missing,
- any `_env` field references an unset/empty env var,
- `tokens.refresh_window < tokens.ttl`.

## Secrets

| Secret               | Source                                      | Rotation |
|----------------------|---------------------------------------------|----------|
| TLS cert/key         | OpenShift secret `ftsgw-server-tls`         | per cert authority policy |
| Signing key          | OpenShift secret `ftsgw-signing-key`        | quarterly (see below) |
| LDAP bind            | OpenShift secret `ftsgw-ldap-bind`          | quarterly |

## Key rotation

1. Generate a new key on a clean host:
   ```
   ftsgw-server rotate-key --out /tmp/signing-2026-04.ed25519
   ```
2. Update `ftsgw-signing-key` secret with the new key and bump the
   `signer.key_id` value in `ftsgw-server-config` (e.g. `ftsgw-2026-02`).
3. Rolling-restart the deployment.
4. New tokens carry the new `kid`; clients that fetch JWKS see the new key
   immediately. Old tokens validate until their `exp` because the broker only
   serves the *current* key; we accept invalidating in-flight tokens.

(Future: serve previous and current keys in JWKS during a rotation window.)

## SQLite backup / restore

The broker holds two tables: `revoked_tokens` and `audit_events`. Both are in
`<audit.file_path dir>/ftsgw.db`.

Backup (broker can stay running thanks to WAL):

```
sqlite3 /var/log/ftsgw-server/ftsgw.db ".backup '/backup/ftsgw-$(date -u +%Y%m%dT%H%M%SZ).db'"
```

Restore: stop the broker, replace the `.db` file, start the broker.

## Log rotation

`audit.log` is rotated by lumberjack (100MB per file, 30-day retention,
compressed). The file is owned by the broker process; non-root.

## Observability

- Prometheus scrape: `https://broker:8443/metrics`.
- OTLP traces: set `OTEL_EXPORTER_OTLP_ENDPOINT=host:4317` (gRPC).
- slog JSON to stdout; ship via OpenShift's `cluster-logging` operator.
