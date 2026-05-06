package onprem

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

// LookupUser finds the user's distinguished name by sAMAccountName.
func (c *Client) LookupUser(sam string) (string, error) {
	req := ldap.NewSearchRequest(
		c.baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		1, 0, false,
		fmt.Sprintf("(&(objectClass=user)(sAMAccountName=%s))", ldap.EscapeFilter(sam)),
		[]string{"distinguishedName", "userPrincipalName"},
		nil,
	)
	res, err := c.conn.Search(req)
	if err != nil {
		return "", fmt.Errorf("looking up user %q: %w", sam, err)
	}
	if len(res.Entries) == 0 {
		return "", fmt.Errorf("user %q not found under %s", sam, c.baseDN)
	}
	c.userDN = res.Entries[0].DN
	return c.userDN, nil
}

// Groups returns the user's group memberships. When nested is true, it expands
// nested groups using the AD-specific matching rule LDAP_MATCHING_RULE_IN_CHAIN
// (1.2.840.113556.1.4.1941). Uses simple paging (RFC 2696) so large result
// sets don't hit the server's per-request size or time limits — recursive
// queries in big directories regularly exceed both.
func (c *Client) Groups(userDN string, nested bool) ([]Group, error) {
	var filter string
	if nested {
		filter = fmt.Sprintf("(member:1.2.840.113556.1.4.1941:=%s)", ldap.EscapeFilter(userDN))
	} else {
		filter = fmt.Sprintf("(member=%s)", ldap.EscapeFilter(userDN))
	}
	req := ldap.NewSearchRequest(
		c.baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false,
		filter,
		[]string{"cn", "distinguishedName"},
		nil,
	)
	const pageSize = 200
	res, err := c.conn.SearchWithPaging(req, pageSize)
	if err != nil {
		return nil, fmt.Errorf("searching groups: %w", err)
	}
	groups := make([]Group, 0, len(res.Entries))
	for _, e := range res.Entries {
		groups = append(groups, Group{
			CN: e.GetAttributeValue("cn"),
			DN: e.DN,
		})
	}
	return groups, nil
}

type Group struct {
	CN string
	DN string
}
