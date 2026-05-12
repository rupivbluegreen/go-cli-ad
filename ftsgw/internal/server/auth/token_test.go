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

package auth_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/auth"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/signer"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/store"
)

type fakeClock struct{ now time.Time }

func (f *fakeClock) Now() time.Time { return f.now }

func mkSigner(t testing.TB) *signer.FileSigner {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	path := filepath.Join(t.TempDir(), "k")
	_ = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv.Seed()}), 0o600)
	s, err := signer.NewFileSigner(path, "kid-1")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return s
}

func mkStore(t testing.TB) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "f.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func newIssuer(t testing.TB, clk auth.Clock) (*auth.Issuer, *store.Store) {
	st := mkStore(t)
	iss, err := auth.NewIssuer(auth.IssuerConfig{
		Signer:        mkSigner(t),
		Store:         st,
		Clock:         clk,
		Issuer:        "ftsgw-server",
		Audience:      "ftsgw",
		TTL:           15 * time.Minute,
		RefreshWindow: 4 * time.Hour,
	})
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	return iss, st
}

func TestMintAndValidate(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 5, 7, 14, 32, 11, 0, time.UTC)}
	iss, _ := newIssuer(t, clk)
	tok, err := iss.Mint(context.Background(), auth.Subject{UPN: "alice@example", Groups: []string{"g1"}})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	c, err := iss.Validate(context.Background(), tok.AccessToken)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if c.Subject != "alice@example" || c.AuthMethod != auth.AuthMethodPassword {
		t.Fatalf("bad claims: %+v", c)
	}
	if !c.IssuedAt.Equal(clk.now) {
		t.Fatalf("iat mismatch")
	}
	if !c.ExpiresAt.Equal(clk.now.Add(15 * time.Minute)) {
		t.Fatalf("exp mismatch")
	}
}

func TestRefreshWithinWindowKeepsIat(t *testing.T) {
	start := time.Date(2026, 5, 7, 14, 0, 0, 0, time.UTC)
	clk := &fakeClock{now: start}
	iss, _ := newIssuer(t, clk)
	tok, _ := iss.Mint(context.Background(), auth.Subject{UPN: "alice@example"})
	clk.now = start.Add(14 * time.Minute) // before TTL
	refreshed, err := iss.Refresh(context.Background(), tok.AccessToken)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	c, _ := iss.Validate(context.Background(), refreshed.AccessToken)
	if !c.IssuedAt.Equal(start) {
		t.Fatalf("iat should be original, got %v", c.IssuedAt)
	}
	if !c.ExpiresAt.Equal(clk.now.Add(15 * time.Minute)) {
		t.Fatalf("exp must be now+ttl")
	}
}

func TestRefreshOutsideWindowRefused(t *testing.T) {
	start := time.Date(2026, 5, 7, 14, 0, 0, 0, time.UTC)
	clk := &fakeClock{now: start}
	iss, _ := newIssuer(t, clk)
	tok, _ := iss.Mint(context.Background(), auth.Subject{UPN: "alice@example"})
	clk.now = start.Add(5 * time.Hour)
	_, err := iss.Refresh(context.Background(), tok.AccessToken)
	if !errors.Is(err, auth.ErrRefreshWindowExhausted) {
		t.Fatalf("got %v", err)
	}
}

func TestRevokedTokenFailsValidate(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 5, 7, 14, 0, 0, 0, time.UTC)}
	iss, st := newIssuer(t, clk)
	tok, _ := iss.Mint(context.Background(), auth.Subject{UPN: "alice@example"})
	c, _ := iss.Validate(context.Background(), tok.AccessToken)
	_ = st.Revoke(context.Background(), c.JTI, c.Subject, "test", c.ExpiresAt)
	if _, err := iss.Validate(context.Background(), tok.AccessToken); !errors.Is(err, auth.ErrRevoked) {
		t.Fatalf("got %v", err)
	}
}

func TestExpiredTokenFailsValidate(t *testing.T) {
	start := time.Date(2026, 5, 7, 14, 0, 0, 0, time.UTC)
	clk := &fakeClock{now: start}
	iss, _ := newIssuer(t, clk)
	tok, _ := iss.Mint(context.Background(), auth.Subject{UPN: "alice@example"})
	clk.now = start.Add(20 * time.Minute)
	if _, err := iss.Validate(context.Background(), tok.AccessToken); !errors.Is(err, auth.ErrExpired) {
		t.Fatalf("got %v", err)
	}
}

func TestBadSignatureFails(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 5, 7, 14, 0, 0, 0, time.UTC)}
	iss, _ := newIssuer(t, clk)
	tok, _ := iss.Mint(context.Background(), auth.Subject{UPN: "alice@example"})
	mutated := tok.AccessToken[:len(tok.AccessToken)-3] + "AAA"
	if _, err := iss.Validate(context.Background(), mutated); err == nil {
		t.Fatalf("want signature error")
	}
}
