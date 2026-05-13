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

package idp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	azauth "github.com/microsoft/kiota-authentication-azure-go"
	khttp "github.com/microsoft/kiota-http-go"
	msgraph "github.com/microsoftgraph/msgraph-sdk-go"
	msgraphcore "github.com/microsoftgraph/msgraph-sdk-go-core"
	"github.com/microsoftgraph/msgraph-sdk-go/models"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/store"
)

// EntraConfig wires an EntraProvider. TenantID and ClientID are required.
type EntraConfig struct {
	TenantID     string
	ClientID     string
	Scopes       []string      // default: ["https://graph.microsoft.com/.default"]
	AuthEndpoint string        // default: "https://login.microsoftonline.com"
	GraphBaseURL string        // overrides the Graph API base URL (for tests)
	Timeout      time.Duration // default: 30s
	Store        *store.Store
	Now          func() time.Time
	CABundlePath string // optional, for corporate proxies / TLS interception
	// HTTPClient overrides the default HTTP client (for tests).
	HTTPClient *http.Client
}

// EntraProvider implements IdentityProvider using the Microsoft Identity
// Platform device-code grant.
type EntraProvider struct {
	cfg  EntraConfig
	http *http.Client
}

// NewEntraProvider constructs and validates an EntraProvider.
func NewEntraProvider(cfg EntraConfig) (*EntraProvider, error) {
	if cfg.TenantID == "" || cfg.ClientID == "" {
		return nil, errors.New("entra: tenant_id and client_id required")
	}
	if cfg.Store == nil {
		return nil, errors.New("entra: store required")
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"https://graph.microsoft.com/.default"}
	}
	if cfg.AuthEndpoint == "" {
		cfg.AuthEndpoint = "https://login.microsoftonline.com"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}

	// Use the caller-supplied HTTP client when provided (tests inject a mock
	// transport). Otherwise build one with the configured TLS settings.
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if cfg.CABundlePath != "" {
			raw, err := os.ReadFile(cfg.CABundlePath)
			if err != nil {
				return nil, fmt.Errorf("ca bundle: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(raw) {
				return nil, errors.New("ca bundle: no PEM certs found")
			}
			tlsCfg.RootCAs = pool
		}
		httpClient = &http.Client{
			Timeout:   cfg.Timeout,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		}
	}

	return &EntraProvider{
		cfg:  cfg,
		http: httpClient,
	}, nil
}

// Authenticate returns ErrNotSupported. EntraProvider only does challenge auth.
func (p *EntraProvider) Authenticate(_ context.Context, _, _ string) (*Identity, error) {
	return nil, ErrNotSupported
}

// InitiateChallenge POSTs to the Microsoft devicecode endpoint and persists
// the resulting challenge in the store.
func (p *EntraProvider) InitiateChallenge(ctx context.Context, hint string) (*Challenge, error) {
	devURL := strings.TrimRight(p.cfg.AuthEndpoint, "/") +
		"/" + url.PathEscape(p.cfg.TenantID) + "/oauth2/v2.0/devicecode"

	form := url.Values{}
	form.Set("client_id", p.cfg.ClientID)
	form.Set("scope", strings.Join(p.cfg.Scopes, " "))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, devURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build devicecode request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("devicecode %d: %s", resp.StatusCode, string(body))
	}

	var dr struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
		ExpiresIn       int    `json:"expires_in"`
		Interval        int    `json:"interval"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&dr); err != nil {
		return nil, fmt.Errorf("decode devicecode response: %w", err)
	}

	now := p.cfg.Now()
	challengeID := newChallengeID(now)

	if err := p.cfg.Store.CreateChallenge(ctx, store.PendingChallenge{
		ID:              challengeID,
		UserHint:        hint,
		DeviceCode:      dr.DeviceCode,
		UserCode:        dr.UserCode,
		VerificationURI: dr.VerificationURI,
		IntervalSeconds: dr.Interval,
		ExpiresAt:       now.Add(time.Duration(dr.ExpiresIn) * time.Second),
		CreatedAt:       now,
	}); err != nil {
		return nil, fmt.Errorf("persist challenge: %w", err)
	}

	return &Challenge{
		ID:              challengeID,
		UserCode:        dr.UserCode,
		VerificationURI: dr.VerificationURI,
		ExpiresIn:       time.Duration(dr.ExpiresIn) * time.Second,
		Interval:        time.Duration(dr.Interval) * time.Second,
	}, nil
}

// CompleteChallenge polls the Microsoft token endpoint and, on success,
// resolves the user's identity via Graph.
func (p *EntraProvider) CompleteChallenge(ctx context.Context, challengeID string) (*Identity, error) {
	ch, err := p.cfg.Store.GetChallenge(ctx, challengeID)
	if err != nil {
		return nil, err
	}

	if p.cfg.Now().After(ch.ExpiresAt) {
		_ = p.cfg.Store.DeleteChallenge(ctx, challengeID)
		return nil, ErrChallengeExpired
	}

	accessToken, err := p.pollToken(ctx, ch.DeviceCode)
	if err != nil {
		return nil, err
	}

	// CAS guard: transitions the row from 'pending' to 'completed' atomically.
	// If a concurrent poll already completed it, ErrChallengeNotFound prevents a
	// double token mint.
	if err := p.cfg.Store.MarkChallengeCompleted(ctx, challengeID); err != nil {
		return nil, err
	}

	id, err := p.resolveGraph(ctx, accessToken)
	if err != nil {
		return nil, fmt.Errorf("graph resolve: %w", err)
	}

	_ = p.cfg.Store.DeleteChallenge(ctx, challengeID)
	return id, nil
}

// pollToken POSTs the device-code token-poll request. It translates Microsoft
// error codes into our sentinel errors.
func (p *EntraProvider) pollToken(ctx context.Context, deviceCode string) (string, error) {
	tokURL := strings.TrimRight(p.cfg.AuthEndpoint, "/") +
		"/" + url.PathEscape(p.cfg.TenantID) + "/oauth2/v2.0/token"

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	form.Set("client_id", p.cfg.ClientID)
	form.Set("device_code", deviceCode)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusOK {
		var tr struct {
			AccessToken string `json:"access_token"`
		}
		if err := json.Unmarshal(body, &tr); err != nil {
			return "", fmt.Errorf("decode token response: %w", err)
		}
		if tr.AccessToken == "" {
			return "", errors.New("entra: empty access_token in response")
		}
		return tr.AccessToken, nil
	}

	var er struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &er)

	switch er.Error {
	case "authorization_pending", "slow_down":
		return "", ErrChallengePending
	case "expired_token", "code_expired":
		return "", ErrChallengeExpired
	case "access_denied":
		return "", ErrAuth
	default:
		return "", fmt.Errorf("token endpoint %d: %s", resp.StatusCode, er.Error)
	}
}

// resolveGraph uses the access token to load the user's UPN, display name,
// and transitive group memberships via msgraph-sdk-go.
func (p *EntraProvider) resolveGraph(ctx context.Context, accessToken string) (*Identity, error) {
	cred := &staticTokenCred{
		accessToken: accessToken,
		expires:     p.cfg.Now().Add(1 * time.Hour),
	}

	// Build the auth provider. Pass the Graph host extracted from GraphBaseURL
	// (if overridden) so the kiota host validator allows it.
	validHosts := []string{"graph.microsoft.com"}
	if p.cfg.GraphBaseURL != "" {
		u, err := url.Parse(p.cfg.GraphBaseURL)
		// Hostname() strips the port; the kiota host validator compares against
		// the bare hostname, so "127.0.0.1:PORT" must be passed as "127.0.0.1".
		if err == nil && u.Hostname() != "" {
			validHosts = []string{u.Hostname()}
		}
	}

	authProvider, err := azauth.NewAzureIdentityAuthenticationProviderWithScopesAndValidHosts(
		cred, p.cfg.Scopes, validHosts,
	)
	if err != nil {
		return nil, fmt.Errorf("graph auth provider: %w", err)
	}

	// Graph routes /me through /users/me-token-to-replace and relies on the
	// UrlReplaceHandler middleware to rewrite it back to /me. Wrap our parent
	// transport (configured TLS or test mock) with the graph middleware chain
	// so that handler is in place.
	graphTransport := khttp.NewCustomTransportWithParentTransport(
		p.http.Transport,
		msgraphcore.GetDefaultMiddlewaresWithOptions(nil)...,
	)
	graphClient := &http.Client{Timeout: p.http.Timeout, Transport: graphTransport}

	adapter, err := msgraph.NewGraphRequestAdapterWithParseNodeFactoryAndSerializationWriterFactoryAndHttpClient(
		authProvider, nil, nil, graphClient,
	)
	if err != nil {
		return nil, fmt.Errorf("graph adapter: %w", err)
	}

	// SetBaseUrl must be called before NewGraphServiceClient: the constructor
	// only sets the default "https://graph.microsoft.com/v1.0" when the base
	// URL is empty, so pre-setting it here redirects all calls (used in tests).
	if p.cfg.GraphBaseURL != "" {
		adapter.SetBaseUrl(p.cfg.GraphBaseURL)
	}

	client := msgraph.NewGraphServiceClient(adapter)

	me, err := client.Me().Get(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("graph /me: %w", err)
	}

	upn := ""
	if v := me.GetUserPrincipalName(); v != nil {
		upn = *v
	}
	display := ""
	if v := me.GetDisplayName(); v != nil {
		display = *v
	}

	members, err := client.Me().TransitiveMemberOf().Get(ctx, nil)
	var groups []string
	if err == nil && members != nil {
		for _, obj := range members.GetValue() {
			switch v := obj.(type) {
			case *models.Group:
				if name := v.GetDisplayName(); name != nil && *name != "" {
					groups = append(groups, *name)
				}
			}
		}
	}

	return &Identity{UPN: upn, DisplayName: display, Groups: groups}, nil
}

// Lookup is not supported by EntraProvider in Phase 1.
func (p *EntraProvider) Lookup(_ context.Context, _ string) (*Identity, error) {
	return nil, ErrNotSupported
}

// HealthCheck verifies the tenant's OpenID configuration is reachable.
func (p *EntraProvider) HealthCheck(ctx context.Context) error {
	metaURL := strings.TrimRight(p.cfg.AuthEndpoint, "/") +
		"/" + url.PathEscape(p.cfg.TenantID) + "/v2.0/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metaURL, nil)
	if err != nil {
		return fmt.Errorf("build healthcheck request: %w", err)
	}

	resp, err := p.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("entra openid config: %s", resp.Status)
	}
	return nil
}

// Capabilities advertises challenge-only authentication.
func (p *EntraProvider) Capabilities() ProviderCapabilities {
	return ProviderCapabilities{SupportsChallenge: true}
}

// newChallengeID returns a time-based opaque ID prefixed with "ch_".
func newChallengeID(t time.Time) string {
	return "ch_" + strconv.FormatInt(t.UnixNano(), 36)
}

// staticTokenCred satisfies azcore.TokenCredential with a fixed access token.
// Used to feed an already-acquired access token into msgraph-sdk-go.
type staticTokenCred struct {
	accessToken string
	expires     time.Time
}

func (s *staticTokenCred) GetToken(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: s.accessToken, ExpiresOn: s.expires}, nil
}
