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
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/cli"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/api"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/audit"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/auth"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/idp"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/signer"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/store"
)

type fixedIdP struct{}

func (fixedIdP) Authenticate(_ context.Context, u, p string) (*idp.Identity, error) {
	if u == "alice" && p == "p" {
		return &idp.Identity{UPN: "alice@example", Groups: []string{"engineers"}}, nil
	}
	return nil, idp.ErrAuth
}
func (fixedIdP) InitiateChallenge(context.Context, string) (*idp.Challenge, error) {
	return nil, idp.ErrNotSupported
}
func (fixedIdP) CompleteChallenge(context.Context, string) (*idp.Identity, error) {
	return nil, idp.ErrNotSupported
}
func (fixedIdP) Lookup(context.Context, string) (*idp.Identity, error) {
	return &idp.Identity{UPN: "alice@example"}, nil
}
func (fixedIdP) HealthCheck(context.Context) error { return nil }
func (fixedIdP) Capabilities() idp.ProviderCapabilities {
	return idp.ProviderCapabilities{SupportsPassword: true}
}

type controlClock struct{ t time.Time }

func (c *controlClock) Now() time.Time { return c.t }

func TestE2EHappyPathAndRefresh(t *testing.T) {
	if os.Getenv("INTEGRATION") == "0" {
		t.Skip("INTEGRATION=0")
	}
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	keyPath := filepath.Join(dir, "k")
	_ = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv.Seed()}), 0o600)
	sgnr, _ := signer.NewFileSigner(keyPath, "kid-1")
	st, _ := store.Open(filepath.Join(dir, "f.db"))
	defer st.Close()
	lg, _ := audit.NewLogger(filepath.Join(dir, "audit.log"), st)
	defer lg.Close()
	clk := &controlClock{t: time.Date(2026, 5, 7, 14, 0, 0, 0, time.UTC)}
	iss, _ := auth.NewIssuer(auth.IssuerConfig{
		Signer: sgnr, Store: st, Clock: clk,
		Issuer: "ftsgw-server", Audience: "ftsgw",
		TTL:    15 * time.Minute, RefreshWindow: 4 * time.Hour,
	})
	deps := &api.Deps{Issuer: iss, IdP: fixedIdP{}, Audit: lg,
		RateLimiter: api.NewRateLimiter(api.RateLimits{PerIPRPS: 1000, PerIPBurst: 1000, AuthPerUsernamePerMinute: 100})}
	srv := httptest.NewServer(api.NewRouter(deps, slog.Default()))
	defer srv.Close()

	tokenPath := filepath.Join(dir, "token.json")
	c, _ := cli.NewClient(cli.ClientConfig{
		BrokerURL: srv.URL, TokenPath: tokenPath, TTLHint: 15 * time.Minute,
		Now: func() time.Time { return clk.t },
	})

	if err := c.Login("alice", "p"); err != nil {
		t.Fatalf("login: %v", err)
	}
	me, err := c.Me()
	if err != nil {
		t.Fatalf("me: %v", err)
	}
	if me.UPN != "alice@example" {
		t.Fatalf("upn = %q", me.UPN)
	}
	clk.t = clk.t.Add(13 * time.Minute)
	if _, err := c.Me(); err != nil {
		t.Fatalf("me-after-refresh: %v", err)
	}
	clk.t = clk.t.Add(5 * time.Hour)
	if _, err := c.Me(); !errors.Is(err, cli.ErrSessionExpired) {
		t.Fatalf("want session expired, got %v", err)
	}
}
