# Phase 1 Notes

Seams already in place for Phase 1 (Entra-native broker on OpenShift with
Entra egress).

## `IdentityProvider` already includes challenge methods

- `InitiateChallenge(ctx, hint) (*Challenge, error)`
- `CompleteChallenge(ctx, challengeID) (*Identity, error)`
- `Capabilities() ProviderCapabilities` advertises `SupportsChallenge`.

Phase 0's `LDAPProvider` returns `ErrNotSupported`. Phase 1's `EntraProvider`
will implement these.

## New table for pending challenges

Phase 1 will add a migration `0002_pending_challenges.sql`:

```sql
CREATE TABLE pending_challenges (
  id          TEXT PRIMARY KEY,
  user_hint   TEXT NULL,
  device_code TEXT NOT NULL,
  user_code   TEXT NOT NULL,
  expires_at  TIMESTAMP NOT NULL,
  created_at  TIMESTAMP NOT NULL
);
```

## Shape of the challenge HTTP response

`POST /v1/auth/token` will optionally return HTTP 202 with this body:

```json
{
  "challenge_id":     "01HX…",
  "user_code":        "ABCD-1234",
  "verification_uri": "https://login.microsoftonline.com/common/oauth2/deviceauth",
  "expires_in_seconds": 900,
  "interval_seconds":   5
}
```

Clients poll `POST /v1/auth/token/complete` with `{"challenge_id":"…"}` until
they get a `TokenResponse` (200) or a terminal error (4xx).

`pkg/api/types/types.go` already has `TokenResponse`; we'll add
`ChallengeResponse` and `CompleteChallengeRequest` there.

## CLI changes

`ftsgw-cli login` will detect a 202 and print the user code + verification
URL to stderr (the broker callback path is already wired similarly in
internal/onprem for the existing go-cli-ad TUI — pattern reusable).

## What stays the same

- Token model (Ed25519, iat/exp/refresh-window).
- Audit shape and event types (`token_issued`, etc.).
- Store schema (`revoked_tokens`).
- HTTP problem-details, middleware order.
- CLI exit codes (challenge flow surfaces under ExitAuthFailed=2).
