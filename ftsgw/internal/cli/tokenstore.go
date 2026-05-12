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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// StoredToken is the on-disk shape of the cached app-token.
type StoredToken struct {
	AccessToken         string    `json:"access_token"`
	ExpiresAt           time.Time `json:"expires_at"`
	RefreshWindowEndsAt time.Time `json:"refresh_window_ends_at"`
	IssuedAt            time.Time `json:"issued_at"`
	BrokerURL           string    `json:"broker_url"`
}

// ErrTokenNotFound is returned when no token file exists.
var ErrTokenNotFound = errors.New("token: not found")

// DefaultTokenPath returns ~/.config/ftsgw/token.json (XDG-compatible).
func DefaultTokenPath() (string, error) {
	cfg, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("user config dir: %w", err)
	}
	return filepath.Join(cfg, "ftsgw", "token.json"), nil
}

// SaveToken writes the token to path with mode 0600.
func SaveToken(path string, t StoredToken) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	b, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal token: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// LoadToken reads and decodes the cached token.
func LoadToken(path string) (StoredToken, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return StoredToken{}, ErrTokenNotFound
		}
		return StoredToken{}, fmt.Errorf("read token: %w", err)
	}
	var t StoredToken
	if err := json.Unmarshal(raw, &t); err != nil {
		return StoredToken{}, fmt.Errorf("decode token: %w", err)
	}
	return t, nil
}

// DeleteToken removes the cache file. Idempotent.
func DeleteToken(path string) error {
	err := os.Remove(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("delete token: %w", err)
	}
	return nil
}
