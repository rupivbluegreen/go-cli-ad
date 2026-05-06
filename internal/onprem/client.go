package onprem

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

type Client struct {
	conn   *ldap.Conn
	baseDN string
	userDN string
}

type DialOptions struct {
	Server             string // ldap:// or ldaps:// URL
	BaseDN             string
	InsecureSkipVerify bool
}

// ErrInvalidCredentials is returned when bind fails with bad creds.
var ErrInvalidCredentials = errors.New("invalid credentials")

// ErrUnreachable is returned when we cannot connect to the LDAP server.
var ErrUnreachable = errors.New("ldap server unreachable")

// Dial opens a connection to the given LDAP/LDAPS URL.
func Dial(opts DialOptions) (*Client, error) {
	u, err := url.Parse(opts.Server)
	if err != nil {
		return nil, fmt.Errorf("parsing server url %q: %w", opts.Server, err)
	}
	var dialOpts []ldap.DialOpt
	if u.Scheme == "ldaps" {
		dialOpts = append(dialOpts, ldap.DialWithTLSConfig(&tls.Config{
			InsecureSkipVerify: opts.InsecureSkipVerify,
			ServerName:         u.Hostname(),
		}))
	}
	conn, err := ldap.DialURL(opts.Server, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	return &Client{conn: conn, baseDN: opts.BaseDN}, nil
}

func (c *Client) Close() {
	if c.conn != nil {
		_ = c.conn.Close()
	}
}

// Bind authenticates using simple bind. Format determines whether to use
// "user@domain" (UPN) or "DOMAIN\user" (down-level).
func (c *Client) Bind(username, password, format, baseDN string) error {
	bindUser, err := buildBindString(username, format, baseDN)
	if err != nil {
		return err
	}
	if err := c.conn.Bind(bindUser, password); err != nil {
		var ldapErr *ldap.Error
		if errors.As(err, &ldapErr) && ldapErr.ResultCode == ldap.LDAPResultInvalidCredentials {
			return ErrInvalidCredentials
		}
		return fmt.Errorf("bind failed: %w", err)
	}
	return nil
}

// buildBindString turns a bare username into a fully-qualified bind string.
// If the user has already provided a UPN ("user@domain") or down-level form
// ("DOMAIN\user"), it's returned unchanged.
func buildBindString(username, format, baseDN string) (string, error) {
	if strings.Contains(username, "@") || strings.Contains(username, `\`) {
		return username, nil
	}
	switch format {
	case "", "upn":
		domain := domainFromBaseDN(baseDN)
		if domain == "" {
			return "", fmt.Errorf("cannot derive UPN domain from base_dn %q; use DOMAIN\\username or user@domain", baseDN)
		}
		return username + "@" + domain, nil
	case "down_level":
		netbios := netbiosFromBaseDN(baseDN)
		if netbios == "" {
			return "", fmt.Errorf("cannot derive NetBIOS domain from base_dn %q", baseDN)
		}
		return netbios + `\` + username, nil
	default:
		return "", fmt.Errorf("unknown bind_format %q (use 'upn' or 'down_level')", format)
	}
}

// domainFromBaseDN turns "DC=corp,DC=example,DC=com" into "corp.example.com".
func domainFromBaseDN(baseDN string) string {
	parts := strings.Split(baseDN, ",")
	var labels []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(strings.ToUpper(p), "DC=") {
			labels = append(labels, p[3:])
		}
	}
	return strings.Join(labels, ".")
}

// netbiosFromBaseDN takes a guess at the NetBIOS short name from the first DC=.
// AD's true NetBIOS name lives in the configuration partition; this is a best-
// effort fallback when the user hasn't given us a fully-qualified bind string.
func netbiosFromBaseDN(baseDN string) string {
	parts := strings.Split(baseDN, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(strings.ToUpper(p), "DC=") {
			return strings.ToUpper(p[3:])
		}
	}
	return ""
}
