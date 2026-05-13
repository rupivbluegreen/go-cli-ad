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

package idp_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/idp"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/store"
)

// openTestStore opens an in-memory-backed SQLite store for tests.
func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// deviceCodeResponse is the JSON returned by the /devicecode endpoint.
type deviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// tokenResponse is the JSON returned by the /token endpoint on success.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

// tokenErrorResponse is the JSON returned by the /token endpoint on 400.
type tokenErrorResponse struct {
	Error string `json:"error"`
}

// mockTransport routes HTTP requests to either the auth handler or the graph
// handler based on URL prefix, making both mockable via a single *http.Client.
type mockTransport struct {
	authServer  *httptest.Server
	graphServer *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Requests whose Host matches the graph server go to graphServer; everything
	// else (login.microsoftonline.com stand-in) goes to authServer.
	if req.URL.Host == m.graphServer.Listener.Addr().String() {
		return m.graphServer.Client().Transport.RoundTrip(req)
	}
	// Rewrite the request host to the auth test server.
	req2 := req.Clone(req.Context())
	req2.URL.Scheme = "http"
	req2.URL.Host = m.authServer.Listener.Addr().String()
	req2.Host = m.authServer.Listener.Addr().String()
	return m.authServer.Client().Transport.RoundTrip(req2)
}

// newEntraProvider builds a test-ready EntraProvider wired to the two httptest
// servers and the supplied store.
func newEntraProvider(
	t *testing.T,
	s *store.Store,
	authSrv *httptest.Server,
	graphSrv *httptest.Server,
	nowFn func() time.Time,
) *idp.EntraProvider {
	t.Helper()
	transport := &mockTransport{authServer: authSrv, graphServer: graphSrv}
	httpClient := &http.Client{Transport: transport}
	p, err := idp.NewEntraProvider(idp.EntraConfig{
		TenantID:     "test-tenant",
		ClientID:     "test-client",
		AuthEndpoint: "http://login.microsoftonline.com", // rewritten by transport
		GraphBaseURL: graphSrv.URL,
		Store:        s,
		Now:          nowFn,
		HTTPClient:   httpClient,
	})
	if err != nil {
		t.Fatalf("NewEntraProvider: %v", err)
	}
	return p
}

// TestEntraInitiateChallengePersists verifies that InitiateChallenge stores the
// challenge row and returns matching fields.
func TestEntraInitiateChallengePersists(t *testing.T) {
	s := openTestStore(t)

	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(deviceCodeResponse{ //nolint:errcheck
			DeviceCode:      "dc-abc",
			UserCode:        "ABCD-1234",
			VerificationURI: "https://microsoft.com/devicelogin",
			ExpiresIn:       900,
			Interval:        5,
		})
	}))
	defer authSrv.Close()

	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unexpected graph call", http.StatusInternalServerError)
	}))
	defer graphSrv.Close()

	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	p := newEntraProvider(t, s, authSrv, graphSrv, func() time.Time { return now })

	ch, err := p.InitiateChallenge(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("InitiateChallenge: %v", err)
	}

	if ch.UserCode != "ABCD-1234" {
		t.Errorf("UserCode = %q, want ABCD-1234", ch.UserCode)
	}
	if ch.VerificationURI != "https://microsoft.com/devicelogin" {
		t.Errorf("VerificationURI = %q", ch.VerificationURI)
	}
	if ch.ExpiresIn != 900*time.Second {
		t.Errorf("ExpiresIn = %v", ch.ExpiresIn)
	}
	if ch.Interval != 5*time.Second {
		t.Errorf("Interval = %v", ch.Interval)
	}
	if ch.ID == "" {
		t.Error("ID must not be empty")
	}

	// Verify the challenge is in the store.
	row, err := s.GetChallenge(context.Background(), ch.ID)
	if err != nil {
		t.Fatalf("GetChallenge: %v", err)
	}
	if row.DeviceCode != "dc-abc" {
		t.Errorf("stored DeviceCode = %q, want dc-abc", row.DeviceCode)
	}
	if row.UserHint != "alice@example.com" {
		t.Errorf("stored UserHint = %q", row.UserHint)
	}
}

// TestEntraCompleteChallengePendingThenSuccess first returns authorization_pending
// then on the second call returns a success token with a mocked Graph response.
func TestEntraCompleteChallengePendingThenSuccess(t *testing.T) {
	s := openTestStore(t)

	// Seed the challenge directly so we don't need to call InitiateChallenge.
	now := time.Now().UTC()
	seedChallenge := store.PendingChallenge{
		ID:              "ch_test_pending",
		UserHint:        "bob@example.com",
		DeviceCode:      "device-code-xyz",
		UserCode:        "WXYZ-5678",
		VerificationURI: "https://microsoft.com/devicelogin",
		IntervalSeconds: 5,
		ExpiresAt:       now.Add(15 * time.Minute),
		CreatedAt:       now,
	}
	if err := s.CreateChallenge(context.Background(), seedChallenge); err != nil {
		t.Fatalf("seed challenge: %v", err)
	}

	var tokenCallCount atomic.Int32
	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := tokenCallCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if count == 1 {
			// First poll: still pending.
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(tokenErrorResponse{Error: "authorization_pending"}) //nolint:errcheck
			return
		}
		// Second poll: success.
		json.NewEncoder(w).Encode(tokenResponse{AccessToken: "fake-access-token", TokenType: "Bearer"}) //nolint:errcheck
	}))
	defer authSrv.Close()

	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/me":
			json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
				"userPrincipalName": "bob@example.com",
				"displayName":       "Bob Builder",
				"@odata.context":    "$metadata#users/$entity",
			})
		case "/me/transitiveMemberOf":
			json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
				"@odata.context": "$metadata#directoryObjects",
				"value": []map[string]interface{}{
					{
						"@odata.type": "#microsoft.graph.group",
						"id":          "g1",
						"displayName": "Developers",
					},
					{
						"@odata.type": "#microsoft.graph.group",
						"id":          "g2",
						"displayName": "AllUsers",
					},
				},
			})
		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer graphSrv.Close()

	p := newEntraProvider(t, s, authSrv, graphSrv, func() time.Time { return now })

	ctx := context.Background()

	// First Complete call should return ErrChallengePending.
	_, err := p.CompleteChallenge(ctx, seedChallenge.ID)
	if !errors.Is(err, idp.ErrChallengePending) {
		t.Fatalf("first complete: got %v, want ErrChallengePending", err)
	}

	// Second Complete call should succeed and return the identity.
	identity, err := p.CompleteChallenge(ctx, seedChallenge.ID)
	if err != nil {
		t.Fatalf("second complete: %v", err)
	}
	if identity.UPN != "bob@example.com" {
		t.Errorf("UPN = %q, want bob@example.com", identity.UPN)
	}
	if identity.DisplayName != "Bob Builder" {
		t.Errorf("DisplayName = %q, want Bob Builder", identity.DisplayName)
	}
	if len(identity.Groups) != 2 {
		t.Errorf("groups count = %d, want 2: %v", len(identity.Groups), identity.Groups)
	}

	// The challenge row should have been deleted after success.
	_, err = s.GetChallenge(ctx, seedChallenge.ID)
	if !errors.Is(err, store.ErrChallengeNotFound) {
		t.Errorf("expected ErrChallengeNotFound after completion, got %v", err)
	}
}

// TestEntraCompleteChallengeExpired verifies that a past-expiry challenge
// returns ErrChallengeExpired.
func TestEntraCompleteChallengeExpired(t *testing.T) {
	s := openTestStore(t)

	past := time.Now().Add(-1 * time.Hour).UTC()
	if err := s.CreateChallenge(context.Background(), store.PendingChallenge{
		ID:              "ch_expired",
		DeviceCode:      "dc-exp",
		UserCode:        "ZZZZ-0000",
		VerificationURI: "https://microsoft.com/devicelogin",
		IntervalSeconds: 5,
		ExpiresAt:       past,
		CreatedAt:       past.Add(-15 * time.Minute),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Auth/graph servers that should never be called for expired challenges.
	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "should not be called", http.StatusInternalServerError)
	}))
	defer authSrv.Close()
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "should not be called", http.StatusInternalServerError)
	}))
	defer graphSrv.Close()

	p := newEntraProvider(t, s, authSrv, graphSrv, func() time.Time { return time.Now().UTC() })

	_, err := p.CompleteChallenge(context.Background(), "ch_expired")
	if !errors.Is(err, idp.ErrChallengeExpired) {
		t.Fatalf("got %v, want ErrChallengeExpired", err)
	}
}

// TestEntraCompleteChallengeAccessDenied verifies that access_denied from the
// token endpoint maps to ErrAuth.
func TestEntraCompleteChallengeAccessDenied(t *testing.T) {
	s := openTestStore(t)

	now := time.Now().UTC()
	if err := s.CreateChallenge(context.Background(), store.PendingChallenge{
		ID:              "ch_denied",
		DeviceCode:      "dc-denied",
		UserCode:        "DENY-1234",
		VerificationURI: "https://microsoft.com/devicelogin",
		IntervalSeconds: 5,
		ExpiresAt:       now.Add(15 * time.Minute),
		CreatedAt:       now,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(tokenErrorResponse{Error: "access_denied"}) //nolint:errcheck
	}))
	defer authSrv.Close()
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "should not be called", http.StatusInternalServerError)
	}))
	defer graphSrv.Close()

	p := newEntraProvider(t, s, authSrv, graphSrv, func() time.Time { return now })

	_, err := p.CompleteChallenge(context.Background(), "ch_denied")
	if !errors.Is(err, idp.ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

// TestEntraCapabilities verifies the provider reports challenge support only.
func TestEntraCapabilities(t *testing.T) {
	s := openTestStore(t)
	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer authSrv.Close()
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer graphSrv.Close()

	p := newEntraProvider(t, s, authSrv, graphSrv, nil)

	caps := p.Capabilities()
	if !caps.SupportsChallenge {
		t.Error("SupportsChallenge should be true")
	}
	if caps.SupportsPassword {
		t.Error("SupportsPassword should be false")
	}
}

// TestEntraAuthenticateReturnsNotSupported verifies that Authenticate is not
// supported by EntraProvider.
func TestEntraAuthenticateReturnsNotSupported(t *testing.T) {
	s := openTestStore(t)
	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer authSrv.Close()
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer graphSrv.Close()

	p := newEntraProvider(t, s, authSrv, graphSrv, nil)

	_, err := p.Authenticate(context.Background(), "alice", "password")
	if !errors.Is(err, idp.ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}
