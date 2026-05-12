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

package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/config"
)

func TestLoadValid(t *testing.T) {
	t.Setenv("FTSGW_LDAP_BIND_DN", "cn=svc,dc=example,dc=com")
	t.Setenv("FTSGW_LDAP_BIND_PASSWORD", "p@ss")
	cfg, err := config.Load(filepath.Join("testdata", "valid.yaml"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Server.ListenAddr != ":8443" {
		t.Fatalf("ListenAddr = %q", cfg.Server.ListenAddr)
	}
	if cfg.Tokens.TTL != 15*time.Minute {
		t.Fatalf("TTL = %v", cfg.Tokens.TTL)
	}
	if cfg.Tokens.RefreshWindow != 4*time.Hour {
		t.Fatalf("RefreshWindow = %v", cfg.Tokens.RefreshWindow)
	}
	if cfg.IdP.ResolvedBindDN != "cn=svc,dc=example,dc=com" {
		t.Fatalf("ResolvedBindDN = %q", cfg.IdP.ResolvedBindDN)
	}
}

func TestLoadMissingRequiredField(t *testing.T) {
	_, err := config.Load(filepath.Join("testdata", "missing_ttl.yaml"))
	if err == nil {
		t.Fatalf("want validation error")
	}
}

func TestLoadMissingEnvSecret(t *testing.T) {
	os.Unsetenv("FTSGW_LDAP_BIND_DN")
	os.Unsetenv("FTSGW_LDAP_BIND_PASSWORD")
	_, err := config.Load(filepath.Join("testdata", "valid.yaml"))
	if err == nil {
		t.Fatalf("want env-secret error")
	}
}
