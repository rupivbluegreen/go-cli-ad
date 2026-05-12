// Copyright 2026 The ftsgw Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package idp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// LDAPConfig is the runtime config for LDAPProvider.
type LDAPConfig struct {
	URL               string
	BaseDN            string
	BindDN            string
	BindPassword      string
	UserSearchFilter  string // e.g. "(userPrincipalName=%s)"
	GroupSearchFilter string // e.g. "(member=%s)"
	CABundlePath      string
	StartTLS          bool
	Timeout           time.Duration
}

// LDAPProvider authenticates against AD/LDAP via simple bind and resolves
// groups via paged search using the AD matching-rule-in-chain OID.
type LDAPProvider struct {
	cfg LDAPConfig
}

// NewLDAPProvider constructs an LDAPProvider. Config is validated by config.Validate.
func NewLDAPProvider(cfg LDAPConfig) *LDAPProvider { return &LDAPProvider{cfg: cfg} }

// Authenticate performs user simple-bind, then re-binds as the service account
// to look up the user record and groups.
func (p *LDAPProvider) Authenticate(ctx context.Context, username, password string) (*Identity, error) {
	conn, err := p.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	if err := conn.Bind(username, password); err != nil {
		var le *ldap.Error
		if errors.As(err, &le) && le.ResultCode == ldap.LDAPResultInvalidCredentials {
			return nil, ErrAuth
		}
		return nil, fmt.Errorf("user bind: %w", err)
	}
	if p.cfg.BindDN != "" {
		if err := conn.Bind(p.cfg.BindDN, p.cfg.BindPassword); err != nil {
			return nil, fmt.Errorf("service bind: %w", err)
		}
	}
	return p.lookupAfterBind(conn, username)
}

// Lookup re-resolves an Identity by UPN using the configured service account.
func (p *LDAPProvider) Lookup(ctx context.Context, upn string) (*Identity, error) {
	conn, err := p.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	if err := conn.Bind(p.cfg.BindDN, p.cfg.BindPassword); err != nil {
		return nil, fmt.Errorf("service bind: %w", err)
	}
	return p.lookupAfterBind(conn, upn)
}

func (p *LDAPProvider) lookupAfterBind(conn *ldap.Conn, username string) (*Identity, error) {
	filter := fmt.Sprintf(p.cfg.UserSearchFilter, escapeFilterValue(username))
	res, err := conn.Search(ldap.NewSearchRequest(
		p.cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		1, int(p.cfg.Timeout.Seconds()), false,
		filter,
		[]string{"distinguishedName", "userPrincipalName", "displayName", "cn"},
		nil,
	))
	if err != nil {
		return nil, fmt.Errorf("user search: %w", err)
	}
	if len(res.Entries) == 0 {
		return nil, ErrAuth
	}
	e := res.Entries[0]
	dn := e.GetAttributeValue("distinguishedName")
	if dn == "" {
		dn = e.DN
	}
	upn := e.GetAttributeValue("userPrincipalName")
	if upn == "" {
		upn = username
	}
	display := e.GetAttributeValue("displayName")
	if display == "" {
		display = e.GetAttributeValue("cn")
	}
	groups, err := p.pagedGroupSearch(conn, dn)
	if err != nil {
		return nil, err
	}
	return &Identity{UPN: upn, DisplayName: display, Groups: groups}, nil
}

// pagedGroupSearch uses LDAP_MATCHING_RULE_IN_CHAIN (1.2.840.113556.1.4.1941)
// and RFC 2696 paged controls to enumerate transitive group membership.
func (p *LDAPProvider) pagedGroupSearch(conn *ldap.Conn, userDN string) ([]string, error) {
	const matchingRuleInChain = "1.2.840.113556.1.4.1941"
	filter := fmt.Sprintf("(member:%s:=%s)", matchingRuleInChain, escapeFilterValue(userDN))
	req := ldap.NewSearchRequest(
		p.cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, int(p.cfg.Timeout.Seconds()), false,
		filter,
		[]string{"cn", "distinguishedName"},
		nil,
	)
	res, err := conn.SearchWithPaging(req, 200)
	if err != nil {
		return nil, fmt.Errorf("group search: %w", err)
	}
	out := make([]string, 0, len(res.Entries))
	for _, e := range res.Entries {
		if cn := e.GetAttributeValue("cn"); cn != "" {
			out = append(out, cn)
		}
	}
	return out, nil
}

// InitiateChallenge — LDAPProvider does not support challenge auth.
func (p *LDAPProvider) InitiateChallenge(_ context.Context, _ string) (*Challenge, error) {
	return nil, ErrNotSupported
}

// CompleteChallenge — LDAPProvider does not support challenge auth.
func (p *LDAPProvider) CompleteChallenge(_ context.Context, _ string) (*Identity, error) {
	return nil, ErrNotSupported
}

// HealthCheck dials, binds as the service account, and disconnects.
func (p *LDAPProvider) HealthCheck(ctx context.Context) error {
	conn, err := p.dial(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if p.cfg.BindDN == "" {
		return nil
	}
	if err := conn.Bind(p.cfg.BindDN, p.cfg.BindPassword); err != nil {
		return fmt.Errorf("health bind: %w", err)
	}
	return nil
}

// Capabilities advertises password support only.
func (p *LDAPProvider) Capabilities() ProviderCapabilities {
	return ProviderCapabilities{SupportsPassword: true}
}

func (p *LDAPProvider) dial(ctx context.Context) (*ldap.Conn, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if p.cfg.CABundlePath != "" {
		raw, err := os.ReadFile(p.cfg.CABundlePath)
		if err != nil {
			return nil, fmt.Errorf("ca bundle: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(raw) {
			return nil, errors.New("ca bundle: no PEM certs found")
		}
		tlsCfg.RootCAs = pool
	}
	conn, err := ldap.DialURL(p.cfg.URL,
		ldap.DialWithTLSConfig(tlsCfg),
		ldap.DialWithDialer(newLDAPDialer(p.cfg.Timeout)),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	conn.SetTimeout(p.cfg.Timeout)
	if p.cfg.StartTLS && !strings.HasPrefix(p.cfg.URL, "ldaps://") {
		if err := conn.StartTLS(tlsCfg); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("starttls: %w", err)
		}
	}
	_ = ctx // reserved for future cancellation
	return conn, nil
}

// escapeFilterValue applies RFC 4515 string-representation escaping.
func escapeFilterValue(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\\':
			b.WriteString(`\5c`)
		case '*':
			b.WriteString(`\2a`)
		case '(':
			b.WriteString(`\28`)
		case ')':
			b.WriteString(`\29`)
		case 0x00:
			b.WriteString(`\00`)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
