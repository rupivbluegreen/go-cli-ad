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

//go:build integration

package integration

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/idp"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestLDAPAuthenticate(t *testing.T) {
	if os.Getenv("INTEGRATION") == "0" {
		t.Skip("INTEGRATION=0")
	}
	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "osixia/openldap:1.5.0",
		ExposedPorts: []string{"389/tcp"},
		Env: map[string]string{
			"LDAP_ORGANISATION":   "Example",
			"LDAP_DOMAIN":         "example.com",
			"LDAP_ADMIN_PASSWORD": "admin",
		},
		WaitingFor: wait.ForLog("slapd starting").WithStartupTimeout(60 * time.Second),
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req, Started: true,
	})
	if err != nil {
		t.Fatalf("container: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(ctx) })
	host, _ := c.Host(ctx)
	port, _ := c.MappedPort(ctx, "389")
	url := "ldap://" + host + ":" + strings.Trim(port.Port(), " ")

	seed := `dn: cn=alice,dc=example,dc=com
objectClass: inetOrgPerson
cn: alice
sn: A
userPassword: hunter2
userPrincipalName: alice@example.com
`
	exitCode, _, err := c.Exec(ctx, []string{"sh", "-c", "echo '" + seed + "' | ldapadd -x -D 'cn=admin,dc=example,dc=com' -w admin"})
	if err != nil || exitCode != 0 {
		t.Fatalf("ldapadd: %v code=%d", err, exitCode)
	}
	p := idp.NewLDAPProvider(idp.LDAPConfig{
		URL: url, BaseDN: "dc=example,dc=com",
		BindDN: "cn=admin,dc=example,dc=com", BindPassword: "admin",
		UserSearchFilter:  "(userPrincipalName=%s)",
		GroupSearchFilter: "(member=%s)",
		Timeout:           10 * time.Second,
	})
	id, err := p.Authenticate(ctx, "cn=alice,dc=example,dc=com", "hunter2")
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if id.UPN != "alice@example.com" {
		t.Fatalf("UPN = %q", id.UPN)
	}
}
