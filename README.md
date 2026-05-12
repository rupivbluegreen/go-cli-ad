# go-cli-ad

A Go CLI that authenticates against on-premises **Active Directory** (LDAP) or
**Azure AD / Entra ID** (device-code flow), then lists the groups and directory
roles the signed-in user belongs to. Ships with a Bubble Tea TUI that auto-launches
when you run the binary with no arguments on a TTY.

## Build

```sh
go build -o bin/go-cli-ad ./cmd/go-cli-ad
```

Requires Go 1.25+.

## First-time setup

```sh
go-cli-ad config init
```

This writes a starter config to `~/.config/go-cli-ad/config.yaml`. Edit it:

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

## Interactive TUI

Run the binary with no arguments on a TTY to launch a Bubble Tea interface
that walks through the same flows:

```sh
go-cli-ad
```

The home menu offers on-prem lookup, Azure sign-in, Azure roles (cached
token), and `config init`. In non-TTY contexts (CI, pipes) the same command
prints help, so existing scripts are unaffected.

Keys: `↑`/`↓` navigate, `enter` select, `esc` back to menu, `ctrl+c` quit.
The on-prem screen prefills server / base DN / username from your config when
present. The Azure sign-in screen renders the verification URL and user code
in a panel and polls until you've completed sign-in in your browser.

## On-premises Active Directory (CLI)

```sh
# Interactive — prompts for password
go-cli-ad onprem login

# Pipe-friendly
echo "$AD_PASSWORD" | go-cli-ad onprem login --password-stdin

# Override config
go-cli-ad onprem login \
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

The password can also come from `$GO_CLI_AD_PASSWORD` if you don't want to use a
prompt or `--password-stdin`.

## Azure AD / Entra ID (CLI)

```sh
# Run device code flow; prints a URL + code, completes after browser sign-in
go-cli-ad azure login

# Re-list using the cached token (no re-auth)
go-cli-ad azure roles

# Expand nested group memberships
go-cli-ad azure login --transitive
```

The access token is cached at `~/.config/go-cli-ad/azure-token.json` (mode
`0600`). When it expires, `go-cli-ad azure roles` will tell you to run
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
go-cli-ad azure login --json | jq '.memberships[] | select(.type=="directoryRole")'
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
cmd/go-cli-ad/main.go            entry point
internal/cli/                    cobra commands; root.go auto-launches TUI on a TTY
internal/tui/                    Bubble Tea screens (home, onprem, azure_login, azure_roles, config_init)
internal/config/                 YAML config loader
internal/onprem/                 LDAP client + nested group search
internal/azure/                  device-code auth + Microsoft Graph queries
internal/output/                 text + JSON renderers
```

## Non-goals

- Kerberos / GSSAPI bind (simple bind only)
- Writing to AD (read-only)
- macOS Keychain / Linux Secret Service token storage (file cache with `0600`
  perms only, for now)

---

## ftsgw — authentication broker + CLI

This repository also ships a second product, **ftsgw**, an authentication
broker (`ftsgw-server`) and its companion CLI (`ftsgw-cli`). It is unrelated
to `go-cli-ad` and lives entirely under `/ftsgw/`.

Quickstart (requires Docker for the demo OpenLDAP):

```sh
make ftsgw-build
make ftsgw-demo
```

`make ftsgw-demo` boots OpenLDAP in a container, seeds a user, runs the
broker against it, then walks `login -> whoami -> status -> logout`.

See:
- `docs/ftsgw/auth-flow.md` — full sequence diagrams.
- `docs/ftsgw/threat-model.md` — STRIDE.
- `docs/ftsgw/deployment.md` — config + secrets + rotation + SQLite backup.
- `DECISIONS.md` — architecture decision records.
- `PHASE_1_NOTES.md` — Entra seams.
