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

package cli_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/cli"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/pkg/api/types"
)

func TestClientAutoRefreshNearExpiry(t *testing.T) {
	var refreshes int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/refresh":
			refreshes++
			_ = json.NewEncoder(w).Encode(types.TokenResponse{
				AccessToken:         "new-token",
				TokenType:           "Bearer",
				ExpiresAt:           time.Now().Add(15 * time.Minute).UTC(),
				RefreshWindowEndsAt: time.Now().Add(3 * time.Hour).UTC(),
			})
		case "/v1/me":
			_ = json.NewEncoder(w).Encode(types.MeResponse{UPN: "alice@example"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token.json")
	now := time.Now().UTC()
	_ = cli.SaveToken(tokenPath, cli.StoredToken{
		AccessToken:         "old-token",
		ExpiresAt:           now.Add(2 * time.Minute), // <20% remaining of 15m
		RefreshWindowEndsAt: now.Add(3 * time.Hour),
		IssuedAt:            now.Add(-13 * time.Minute),
		BrokerURL:           srv.URL,
	})

	c, _ := cli.NewClient(cli.ClientConfig{
		BrokerURL: srv.URL,
		TokenPath: tokenPath,
		TTLHint:   15 * time.Minute,
	})
	_, err := c.Me()
	if err != nil {
		t.Fatalf("Me: %v", err)
	}
	if refreshes != 1 {
		t.Fatalf("refreshes = %d, want 1", refreshes)
	}
	got, _ := cli.LoadToken(tokenPath)
	if got.AccessToken != "new-token" {
		t.Fatalf("token not updated")
	}
}

func TestClientSurfacesSessionExpired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "expired", http.StatusUnauthorized)
	}))
	defer srv.Close()

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token.json")
	past := time.Now().Add(-1 * time.Hour).UTC()
	_ = cli.SaveToken(tokenPath, cli.StoredToken{
		AccessToken: "old", ExpiresAt: past, RefreshWindowEndsAt: past,
		IssuedAt: past.Add(-4 * time.Hour), BrokerURL: srv.URL,
	})
	c, _ := cli.NewClient(cli.ClientConfig{
		BrokerURL: srv.URL,
		TokenPath: tokenPath,
		TTLHint:   15 * time.Minute,
	})
	_, err := c.Me()
	if err == nil {
		t.Fatalf("want session expired error")
	}
}
