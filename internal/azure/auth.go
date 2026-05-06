package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

const GraphScope = "https://graph.microsoft.com/.default"

// CachedToken is what we persist to disk after a successful device-code flow.
type CachedToken struct {
	AccessToken string    `json:"access_token"`
	ExpiresAt   time.Time `json:"expires_at"`
	TenantID    string    `json:"tenant_id"`
	ClientID    string    `json:"client_id"`
}

// ErrNoCachedToken is returned when the cache file does not exist.
var ErrNoCachedToken = errors.New("no cached token; run 'rogi-cli azure login'")

// ErrTokenExpired is returned when the cached token has expired.
var ErrTokenExpired = errors.New("cached token expired; run 'rogi-cli azure login'")

// TokenCachePath returns the conventional location for the token cache file.
func TokenCachePath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locating user config dir: %w", err)
	}
	return filepath.Join(dir, "rogi-cli", "azure-token.json"), nil
}

// DeviceCodeLogin runs the device code flow, prints the user prompt to stderr,
// and returns a credential plus the resulting access token.
func DeviceCodeLogin(ctx context.Context, tenantID, clientID string, prompt func(string)) (azcore.TokenCredential, *CachedToken, error) {
	cred, err := azidentity.NewDeviceCodeCredential(&azidentity.DeviceCodeCredentialOptions{
		TenantID: tenantID,
		ClientID: clientID,
		UserPrompt: func(_ context.Context, m azidentity.DeviceCodeMessage) error {
			prompt(m.Message)
			return nil
		},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("creating device code credential: %w", err)
	}
	tok, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{GraphScope}})
	if err != nil {
		return nil, nil, fmt.Errorf("device code login failed: %w", err)
	}
	cached := &CachedToken{
		AccessToken: tok.Token,
		ExpiresAt:   tok.ExpiresOn,
		TenantID:    tenantID,
		ClientID:    clientID,
	}
	return cred, cached, nil
}

// SaveToken writes the cached token to disk with 0600 permissions.
func SaveToken(path string, t *CachedToken) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating cache dir: %w", err)
	}
	data, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// LoadToken reads a previously cached token. Returns ErrNoCachedToken if the
// file is missing and ErrTokenExpired if the token is past its expiry.
func LoadToken(path string) (*CachedToken, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoCachedToken
		}
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var t CachedToken
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	// Treat anything within the next 60s as expired so we don't hand out a
	// token that will fail mid-request.
	if time.Now().Add(60 * time.Second).After(t.ExpiresAt) {
		return nil, ErrTokenExpired
	}
	return &t, nil
}

// staticCredential is an azcore.TokenCredential backed by a previously-acquired
// access token. It's used when reusing a cached token from disk; if the token
// has expired, callers must re-run the device code flow.
type staticCredential struct {
	token CachedToken
}

func (s *staticCredential) GetToken(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	if time.Now().After(s.token.ExpiresAt) {
		return azcore.AccessToken{}, ErrTokenExpired
	}
	return azcore.AccessToken{Token: s.token.AccessToken, ExpiresOn: s.token.ExpiresAt}, nil
}

// CredentialFromCache wraps a CachedToken as an azcore.TokenCredential.
func CredentialFromCache(t *CachedToken) azcore.TokenCredential {
	return &staticCredential{token: *t}
}
