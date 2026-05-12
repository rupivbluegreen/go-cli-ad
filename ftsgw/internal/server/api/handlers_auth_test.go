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

package api_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/api"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/audit"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/auth"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/idp"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/signer"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/store"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/pkg/api/types"
)

type stubIdP struct {
	id  *idp.Identity
	err error
}

func (s stubIdP) Authenticate(_ context.Context, _, _ string) (*idp.Identity, error) {
	return s.id, s.err
}
func (s stubIdP) InitiateChallenge(context.Context, string) (*idp.Challenge, error) {
	return nil, idp.ErrNotSupported
}
func (s stubIdP) CompleteChallenge(context.Context, string) (*idp.Identity, error) {
	return nil, idp.ErrNotSupported
}
func (s stubIdP) Lookup(context.Context, string) (*idp.Identity, error) { return s.id, s.err }
func (s stubIdP) HealthCheck(context.Context) error                     { return nil }
func (s stubIdP) Capabilities() idp.ProviderCapabilities {
	return idp.ProviderCapabilities{SupportsPassword: true}
}

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

func mkBrokerDeps(t *testing.T, p idp.IdentityProvider) (*api.Deps, *auth.Issuer) {
	t.Helper()
	dir := t.TempDir()
	st, _ := store.Open(filepath.Join(dir, "f.db"))
	t.Cleanup(func() { _ = st.Close() })
	lg, _ := audit.NewLogger(filepath.Join(dir, "audit.log"), st)
	t.Cleanup(func() { _ = lg.Close() })
	sgnr := mkSigner(t)
	iss, _ := auth.NewIssuer(auth.IssuerConfig{
		Signer: sgnr, Store: st, Clock: auth.RealClock{},
		Issuer: "ftsgw-server", Audience: "ftsgw",
		TTL: 15 * time.Minute, RefreshWindow: 4 * time.Hour,
	})
	return &api.Deps{Issuer: iss, IdP: p, Audit: lg, RateLimiter: api.NewRateLimiter(api.RateLimits{
		PerIPRPS: 1000, PerIPBurst: 1000, AuthPerUsernamePerMinute: 100,
	})}, iss
}

func TestTokenHandlerSuccess(t *testing.T) {
	deps, _ := mkBrokerDeps(t, stubIdP{id: &idp.Identity{UPN: "alice@example", Groups: []string{"g1"}}})
	body, _ := json.Marshal(types.TokenRequest{Username: "alice", Password: "p"})
	r := httptest.NewRequest(http.MethodPost, "/v1/auth/token", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	api.HandleTokenIssue(deps).ServeHTTP(rr, r)
	if rr.Code != 200 {
		t.Fatalf("code = %d body=%s", rr.Code, rr.Body.String())
	}
	var resp types.TokenResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.AccessToken == "" || resp.TokenType != "Bearer" {
		t.Fatalf("bad resp: %+v", resp)
	}
}

func TestTokenHandlerRejectsBadCreds(t *testing.T) {
	deps, _ := mkBrokerDeps(t, stubIdP{err: idp.ErrAuth})
	body, _ := json.Marshal(types.TokenRequest{Username: "alice", Password: "wrong"})
	r := httptest.NewRequest(http.MethodPost, "/v1/auth/token", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	api.HandleTokenIssue(deps).ServeHTTP(rr, r)
	if rr.Code != 401 {
		t.Fatalf("code = %d", rr.Code)
	}
}

func TestRefreshHandlerSuccess(t *testing.T) {
	deps, iss := mkBrokerDeps(t, stubIdP{id: &idp.Identity{UPN: "alice@example"}})
	tok, _ := iss.Mint(context.Background(), auth.Subject{UPN: "alice@example"})
	r := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", nil)
	r.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	rr := httptest.NewRecorder()
	api.HandleTokenRefresh(deps).ServeHTTP(rr, r)
	if rr.Code != 200 {
		t.Fatalf("code = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestLogoutRevokes(t *testing.T) {
	deps, iss := mkBrokerDeps(t, stubIdP{id: &idp.Identity{UPN: "alice@example"}})
	tok, _ := iss.Mint(context.Background(), auth.Subject{UPN: "alice@example"})
	r := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	r.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	rr := httptest.NewRecorder()
	api.HandleLogout(deps).ServeHTTP(rr, r)
	if rr.Code != 204 {
		t.Fatalf("code = %d", rr.Code)
	}
	if _, err := iss.Validate(context.Background(), tok.AccessToken); err == nil {
		t.Fatalf("token should now be revoked")
	}
}
