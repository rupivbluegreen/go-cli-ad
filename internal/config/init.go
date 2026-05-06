package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const starterTemplate = `# rogi-cli configuration
# On-premises Active Directory (LDAP)
onprem:
  server: ldaps://dc.corp.example.com:636
  base_dn: DC=corp,DC=example,DC=com
  username:                  # optional default; override with --username
  bind_format: upn           # "upn" => user@domain  |  "down_level" => DOMAIN\user

# Azure AD / Entra ID (device code flow)
azure:
  tenant_id: common          # or a specific tenant GUID
  client_id: 04b07795-8ddb-461a-bbee-02f9e1bf7b46  # Azure CLI public client
`

var ErrAlreadyExists = errors.New("config file already exists")

func WriteStarter(path string, force bool) error {
	if _, err := os.Stat(path); err == nil && !force {
		return ErrAlreadyExists
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}
	if err := os.WriteFile(path, []byte(starterTemplate), 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}
