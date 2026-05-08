---
layout: default
title: go-cli-ad
---

# go-cli-ad

A small Go CLI that authenticates against **on-premises Active Directory**
(LDAP) or **Azure AD / Entra ID** (device code flow), then lists the groups
and directory roles you belong to.

[View on GitHub](https://github.com/rupivbluegreen/go-cli-ad){: .btn }

---

## Why

If you've ever wondered *exactly* which AD groups or Entra roles your account
belongs to — including ones inherited through nested groups — `go-cli-ad`
gives you a one-line answer from the terminal. It works against either
backend with the same UX:

- One subcommand tree per backend (`onprem` / `azure`)
- Bubble Tea TUI auto-launches when you run the bare binary on a TTY
- Plain text by default, `--json` for piping into `jq`
- Recursive group expansion on by default for on-prem (`LDAP_MATCHING_RULE_IN_CHAIN`)
- Device code flow for Azure — works with MFA and conditional access
- Distinct exit codes so scripts can react to auth, network, and query errors separately

## Install

Requires Go 1.25+.

```sh
git clone https://github.com/rupivbluegreen/go-cli-ad
cd go-cli-ad
go build -o bin/go-cli-ad ./cmd/go-cli-ad
```

## First-time setup

```sh
go-cli-ad config init
```

Writes a starter config to `~/.config/go-cli-ad/config.yaml`:

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

## Use

### Interactive TUI

```sh
go-cli-ad
```

With no arguments on a TTY, the binary launches a Bubble Tea interface with
a home menu for on-prem lookup, Azure sign-in, Azure roles (cached token),
and `config init`. In non-TTY contexts (CI, pipes) the same command prints
help. Keys: `↑`/`↓` navigate, `enter` select, `esc` back, `ctrl+c` quit.

### On-premises Active Directory

```sh
go-cli-ad onprem login
# Password: ********
# ✓ Authenticated as CN=Alex P,OU=Users,DC=corp,DC=example,DC=com
#
# Memberships (5):
#   [G] Domain Users
#   [G] VPN-Users
#   [G] Engineering
#   [G] GitHub-SSO
#   [G] Backup-Operators
```

### Azure AD / Entra ID

```sh
go-cli-ad azure login
# To sign in, use a web browser to open https://microsoft.com/devicelogin
# and enter the code XXXXXXXXX to authenticate.
# ✓ Authenticated as alex@corp.example.com
#
# Memberships (3):
#   [R] Global Reader
#   [G] Engineering
#   [G] All Company

go-cli-ad azure roles            # reuse cached token
go-cli-ad azure login --transitive   # expand nested groups
```

### JSON output

```sh
go-cli-ad azure login --json | jq '.memberships[] | select(.type=="directoryRole")'
```

```json
{
  "authenticated_as": "alex@corp.example.com",
  "memberships": [
    {"type": "directoryRole", "name": "Global Reader", "id": "..."},
    {"type": "group",         "name": "Engineering",   "id": "..."}
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
- macOS Keychain / Linux Secret Service token storage (file cache with `0600` perms only, for now)

---

[Source on GitHub](https://github.com/rupivbluegreen/go-cli-ad) · MIT-style license forthcoming
