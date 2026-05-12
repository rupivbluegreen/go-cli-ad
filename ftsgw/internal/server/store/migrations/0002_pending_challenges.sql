-- +goose Up
CREATE TABLE pending_challenges (
  id          TEXT PRIMARY KEY,
  user_hint   TEXT NULL,
  device_code TEXT NOT NULL,
  user_code   TEXT NOT NULL,
  verification_uri TEXT NOT NULL,
  interval_seconds INTEGER NOT NULL,
  expires_at  TIMESTAMP NOT NULL,
  created_at  TIMESTAMP NOT NULL,
  state       TEXT NOT NULL DEFAULT 'pending'
);
CREATE INDEX idx_pending_challenges_exp ON pending_challenges(expires_at);

-- +goose Down
DROP TABLE pending_challenges;
