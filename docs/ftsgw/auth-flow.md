# ftsgw Authentication Flow

This document covers the complete password-auth lifecycle in Phase 0 (Mode 3, fully disconnected).

## First login

```mermaid
sequenceDiagram
  participant U as User
  participant C as ftsgw-cli
  participant B as ftsgw-server
  participant L as AD/LDAP

  U->>C: ftsgw-cli login
  C->>U: prompt username + password (no echo)
  C->>B: POST /v1/auth/token {username, password}
  B->>L: LDAP simple bind (user)
  L-->>B: success
  B->>L: paged group search (matching-rule-in-chain)
  L-->>B: groups
  B->>B: Mint Ed25519 JWT (iat=now, exp=now+15m)
  B->>B: audit token_issued
  B-->>C: 200 TokenResponse
  C->>C: persist ~/.config/ftsgw/token.json (0600)
```

## Auto refresh (80% of TTL elapsed)

```mermaid
sequenceDiagram
  participant C as ftsgw-cli
  participant B as ftsgw-server

  C->>C: before request, check token state
  Note over C: now >= exp - (ttl*0.2)
  C->>B: POST /v1/auth/refresh (Bearer current)
  B->>B: verify signature + revocation
  B->>B: check now - iat <= refresh_window
  B->>B: Mint new JWT (iat preserved, exp=now+15m)
  B->>B: audit token_refreshed
  B-->>C: 200 TokenResponse
  C->>C: persist new token (iat unchanged)
```

## Refresh window exhausted

```mermaid
sequenceDiagram
  participant C as ftsgw-cli
  participant B as ftsgw-server

  C->>B: POST /v1/auth/refresh
  B->>B: now - iat > 4h
  B->>B: audit token_refresh_refused
  B-->>C: 401 ProblemDetails
  C->>C: surface "session expired, run ftsgw-cli login"
  C->>C: exit 4
```

## Idle expiry (token expired before next command)

```mermaid
sequenceDiagram
  participant C as ftsgw-cli
  participant B as ftsgw-server

  C->>C: now > token.expires_at
  alt now < refresh_window_ends_at
    C->>B: POST /v1/auth/refresh
    B-->>C: 200 new token
  else
    C->>C: surface "session expired"
    C->>C: exit 4
  end
```

## Logout

```mermaid
sequenceDiagram
  participant C as ftsgw-cli
  participant B as ftsgw-server

  C->>B: POST /v1/auth/logout (Bearer)
  B->>B: insert jti -> revoked_tokens
  B->>B: audit token_revoked
  B-->>C: 204
  C->>C: rm ~/.config/ftsgw/token.json
```
