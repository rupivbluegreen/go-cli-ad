# rogi-cli

A Go CLI that authenticates against on-premises **Active Directory** (LDAP) or
**Azure AD / Entra ID** (device-code flow), then lists the groups and directory
roles the signed-in user belongs to.

## Build

```sh
go build -o bin/rogi-cli ./cmd/rogi-cli
```

Requires Go 1.24+.

## First-time setup

```sh
rogi-cli config init
```

This writes a starter config to `~/.config/rogi-cli/config.yaml`. Edit it:

```yaml
onprem:
  server: ldaps://dc.corp.example.com:636
  base_dn: DC=corp,DC=example,DC=com
  username:                  # optional default; override with --username
  bind_format: upn           # "upn" => user@domain  |  "down_level" => DOMAIN\user

azure:
  tenant_id: common          # or a specific tenant GUID
  client_id: 04b07795-8ddb-461a-bbee-02f9e1bf7b46  # Azure CLI public client
```

## On-premises Active Directory

```sh
# Interactive — prompts for password
rogi-cli onprem login

# Pipe-friendly
echo "$AD_PASSWORD" | rogi-cli onprem login --password-stdin

# Override config
rogi-cli onprem login \
  --server ldaps://dc.corp.example.com \
  --base-dn DC=corp,DC=example,DC=com \
  --username alex
```

Flags:

| Flag | Purpose |
|---|---|
| `--username` | Username (defaults to config, then `$USER`) |
| `--password-stdin` | Read password from stdin instead of prompting |
| `--server` | LDAP server URL override |
| `--base-dn` | Base DN override |
| `--insecure-skip-verify` | Skip TLS verification (lab use only) |
| `--no-nested` | Direct group memberships only (skip recursive expansion) |

Group recursion uses the AD-specific matching rule
`LDAP_MATCHING_RULE_IN_CHAIN` (`1.2.840.113556.1.4.1941`).

The password can also come from `$ROGI_PASSWORD` if you don't want to use a
prompt or `--password-stdin`.

## Azure AD / Entra ID

```sh
# Run device code flow; prints a URL + code, completes after browser sign-in
rogi-cli azure login

# Re-list using the cached token (no re-auth)
rogi-cli azure roles

# Expand nested group memberships
rogi-cli azure login --transitive
```

The access token is cached at `~/.config/rogi-cli/azure-token.json` (mode
`0600`). When it expires, `rogi-cli azure roles` will tell you to run
`azure login` again.

## Output

Plain text by default:

```
✓ Authenticated as alex@corp.example.com

Memberships (3):
  [R] Global Reader
  [G] Engineering
  [G] All Company
```

`--json` for scripts:

```sh
rogi-cli azure login --json | jq '.memberships[] | select(.type=="directoryRole")'
```

```json
{
  "authenticated_as": "alex@corp.example.com",
  "memberships": [
    {"type": "directoryRole", "name": "Global Reader", "id": "..."},
    {"type": "group", "name": "Engineering", "id": "..."}
  ]
}
```

## Exit codes

| Code | Meaning |
|---|---|
| `1` | Invalid credentials / auth failure |
| `2` | Network or connection error |
| `3` | Device code timed out / token expired |
| `4` | Config not found or invalid |
| `5` | Post-auth query error (LDAP search, Graph call) |

## Troubleshooting

- **`bind failed: invalid credentials`** — check `bind_format` in your config.
  AD usually accepts both `user@corp.example.com` (UPN) and `CORP\user`
  (down-level); pick the one your DC is happy with.
- **`x509: certificate signed by unknown authority`** — your LDAPS server uses
  an internal CA. Either install the CA cert in your system trust store or use
  `--insecure-skip-verify` for testing.
- **Azure: `AADSTS70011: scope is not valid`** — change the requested scope, or
  register your own Azure app with `User.Read`, `Directory.Read.All`, and the
  device-code flow enabled, then put its `client_id` in the config.
- **Azure: device code times out** — re-run `azure login`. The window is short
  (~15 minutes).

## Layout

```
cmd/rogi-cli/main.go            entry point
internal/cli/                   cobra commands
internal/config/                YAML config loader
internal/onprem/                LDAP client + nested group search
internal/azure/                 device-code auth + Microsoft Graph queries
internal/output/                text + JSON renderers
```

## Non-goals

- Kerberos / GSSAPI bind (simple bind only)
- Writing to AD (read-only)
- macOS Keychain / Linux Secret Service token storage (file cache with `0600`
  perms only, for now)
