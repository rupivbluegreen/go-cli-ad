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

package cli

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/pkg/api/types"
)

// ErrSessionExpired surfaces "your refresh window is gone, log in again".
var ErrSessionExpired = errors.New("session expired")

// ErrAuth is the CLI's user-visible "bad password" sentinel.
var ErrAuth = errors.New("authentication failed")

// ClientConfig wires a CLI HTTP client.
type ClientConfig struct {
	BrokerURL    string
	TokenPath    string
	CABundlePath string
	TTLHint      time.Duration // server-side TTL (used to decide when to auto-refresh)
	Now          func() time.Time
}

// Client is the broker-facing HTTP client.
type Client struct {
	cfg  ClientConfig
	http *http.Client
}

// NewClient validates config and constructs the client.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.BrokerURL == "" {
		return nil, errors.New("client: broker URL required")
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	if cfg.TTLHint == 0 {
		cfg.TTLHint = 15 * time.Minute
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CABundlePath != "" {
		raw, err := os.ReadFile(cfg.CABundlePath)
		if err != nil {
			return nil, fmt.Errorf("ca bundle: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(raw) {
			return nil, errors.New("ca bundle: no certs")
		}
		tlsCfg.RootCAs = pool
	}
	return &Client{
		cfg: cfg,
		http: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
	}, nil
}

// Login posts username/password to /v1/auth/token and stores the result.
func (c *Client) Login(username, password string) error {
	body, _ := json.Marshal(types.TokenRequest{Username: username, Password: password})
	resp, err := c.http.Post(c.cfg.BrokerURL+"/v1/auth/token", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("post token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized {
		return ErrAuth
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("login: %s", resp.Status)
	}
	var tr types.TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return fmt.Errorf("decode token: %w", err)
	}
	return SaveToken(c.cfg.TokenPath, StoredToken{
		AccessToken:         tr.AccessToken,
		ExpiresAt:           tr.ExpiresAt,
		RefreshWindowEndsAt: tr.RefreshWindowEndsAt,
		IssuedAt:            c.cfg.Now(),
		BrokerURL:           c.cfg.BrokerURL,
	})
}

// Me returns identity from /v1/me, auto-refreshing on near-expiry.
func (c *Client) Me() (*types.MeResponse, error) {
	tok, err := c.ensureFresh()
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequest(http.MethodGet, c.cfg.BrokerURL+"/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get /me: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("me: %s", resp.Status)
	}
	var me types.MeResponse
	if err := json.NewDecoder(resp.Body).Decode(&me); err != nil {
		return nil, fmt.Errorf("decode me: %w", err)
	}
	return &me, nil
}

// Logout calls /v1/auth/logout and deletes the local token cache.
func (c *Client) Logout() error {
	tok, err := LoadToken(c.cfg.TokenPath)
	if err != nil {
		if errors.Is(err, ErrTokenNotFound) {
			return nil
		}
		return err
	}
	req, _ := http.NewRequest(http.MethodPost, c.cfg.BrokerURL+"/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("post /logout: %w", err)
	}
	_ = resp.Body.Close()
	return DeleteToken(c.cfg.TokenPath)
}

// ensureFresh loads the cached token and refreshes it if past 80% of TTL.
// If the token is past exp and the refresh window has also elapsed, returns
// ErrSessionExpired so callers can surface a clean "run ftsgw-cli login".
func (c *Client) ensureFresh() (*StoredToken, error) {
	tok, err := LoadToken(c.cfg.TokenPath)
	if err != nil {
		return nil, err
	}
	now := c.cfg.Now()
	if now.After(tok.RefreshWindowEndsAt) {
		return nil, ErrSessionExpired
	}
	refreshAt := tok.ExpiresAt.Add(-c.cfg.TTLHint / 5) // 80% of TTL elapsed
	if now.Before(refreshAt) {
		return &tok, nil
	}
	req, _ := http.NewRequest(http.MethodPost, c.cfg.BrokerURL+"/v1/auth/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	resp, err := c.http.Do(req)
	if err != nil {
		if now.Before(tok.ExpiresAt) {
			return &tok, nil
		}
		return nil, fmt.Errorf("refresh: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, ErrSessionExpired
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("refresh: %s", resp.Status)
	}
	var tr types.TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, fmt.Errorf("decode refresh: %w", err)
	}
	updated := StoredToken{
		AccessToken:         tr.AccessToken,
		ExpiresAt:           tr.ExpiresAt,
		RefreshWindowEndsAt: tr.RefreshWindowEndsAt,
		IssuedAt:            tok.IssuedAt, // preserved
		BrokerURL:           tok.BrokerURL,
	}
	if err := SaveToken(c.cfg.TokenPath, updated); err != nil {
		return nil, err
	}
	return &updated, nil
}
