---
layout: default
title: rogi-cli
---

# rogi-cli

A small Go CLI that authenticates against **on-premises Active Directory**
(LDAP) or **Azure AD / Entra ID** (device code flow), then lists the groups
and directory roles you belong to.

[View on GitHub](https://github.com/rupivbluegreen/rogi-cli){: .btn }

---

## Why

If you've ever wondered *exactly* which AD groups or Entra roles your account
belongs to — including ones inherited through nested groups — `rogi-cli`
gives you a one-line answer from the terminal. It works against either
backend with the same UX:

- One subcommand tree per backend (`onprem` / `azure`)
- Plain text by default, `--json` for piping into `jq`
- Recursive group expansion on by default for on-prem (`LDAP_MATCHING_RULE_IN_CHAIN`)
- Device code flow for Azure — works with MFA and conditional access
- Distinct exit codes so scripts can react to auth, network, and query errors separately

## Install

Requires Go 1.24+.

```sh
git clone https://github.com/rupivbluegreen/rogi-cli
cd rogi-cli
go build -o bin/rogi-cli ./cmd/rogi-cli
```

## First-time setup

```sh
rogi-cli config init
```

Writes a starter config to `~/.config/rogi-cli/config.yaml`:

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

### On-premises Active Directory

```sh
rogi-cli onprem login
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
rogi-cli azure login
# To sign in, use a web browser to open https://microsoft.com/devicelogin
# and enter the code XXXXXXXXX to authenticate.
# ✓ Authenticated as alex@corp.example.com
#
# Memberships (3):
#   [R] Global Reader
#   [G] Engineering
#   [G] All Company

rogi-cli azure roles            # reuse cached token
rogi-cli azure login --transitive   # expand nested groups
```

### JSON output

```sh
rogi-cli azure login --json | jq '.memberships[] | select(.type=="directoryRole")'
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
- macOS Keychain / Linux Secret Service token storage (file cache with `0600` perms only, for now)

---

[Source on GitHub](https://github.com/rupivbluegreen/rogi-cli) · MIT-style license forthcoming
