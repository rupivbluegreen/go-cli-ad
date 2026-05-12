-- +goose Up
CREATE TABLE revoked_tokens (
  jti        TEXT PRIMARY KEY,
  revoked_at TIMESTAMP NOT NULL,
  exp        TIMESTAMP NOT NULL,
  actor_upn  TEXT NOT NULL,
  reason     TEXT NULL
);
CREATE INDEX idx_revoked_exp ON revoked_tokens(exp);

CREATE TABLE audit_events (
  id           TEXT PRIMARY KEY,
  ts           TIMESTAMP NOT NULL,
  actor_upn    TEXT NULL,
  event_type   TEXT NOT NULL,
  outcome      TEXT NOT NULL,
  reason       TEXT NULL,
  client_ip    TEXT NULL,
  request_id   TEXT NOT NULL,
  trace_id     TEXT NULL,
  payload_json TEXT NOT NULL
);
CREATE INDEX idx_audit_ts    ON audit_events(ts);
CREATE INDEX idx_audit_actor ON audit_events(actor_upn, ts);

-- +goose Down
DROP TABLE audit_events;
DROP TABLE revoked_tokens;
