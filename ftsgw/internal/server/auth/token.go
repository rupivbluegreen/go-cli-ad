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

// Package auth mints, refreshes, and validates ftsgw app-tokens (Ed25519 JWTs).
//
// The `iat` claim records ORIGINAL password authentication time and is
// preserved across refreshes. `exp` moves forward by TTL on every refresh.
// Refresh is refused when (now - iat) > RefreshWindow.
package auth

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/signer"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/store"
)

// Sentinel errors. Wrapped at boundaries.
var (
	ErrExpired                = errors.New("token: expired")
	ErrRevoked                = errors.New("token: revoked")
	ErrInvalidSignature       = errors.New("token: invalid signature")
	ErrInvalidClaims          = errors.New("token: invalid claims")
	ErrRefreshWindowExhausted = errors.New("token: refresh window exhausted")
)

// Subject is the input to Mint.
type Subject struct {
	UPN    string
	Groups []string
	Roles  []string
}

// IssuedToken is the wire-friendly mint result.
type IssuedToken struct {
	AccessToken         string
	ExpiresAt           time.Time
	RefreshWindowEndsAt time.Time
	IssuedAt            time.Time
	JTI                 string
}

// IssuerConfig wires everything Issuer needs.
type IssuerConfig struct {
	Signer        signer.Signer
	Store         *store.Store
	Clock         Clock
	Issuer        string
	Audience      string
	TTL           time.Duration
	RefreshWindow time.Duration
}

// Issuer is the only thing that touches Signer + Store for tokens.
type Issuer struct {
	cfg IssuerConfig
}

// NewIssuer returns a configured Issuer. Validates inputs eagerly.
func NewIssuer(cfg IssuerConfig) (*Issuer, error) {
	if cfg.Signer == nil || cfg.Store == nil || cfg.Clock == nil {
		return nil, errors.New("auth: signer, store, clock required")
	}
	if cfg.TTL <= 0 || cfg.RefreshWindow <= 0 {
		return nil, errors.New("auth: ttl and refresh_window must be > 0")
	}
	if cfg.Issuer == "" || cfg.Audience == "" {
		return nil, errors.New("auth: issuer and audience required")
	}
	return &Issuer{cfg: cfg}, nil
}

// Mint issues a fresh token. `iat` = clock.Now(), `exp` = iat + TTL.
func (i *Issuer) Mint(ctx context.Context, s Subject) (*IssuedToken, error) {
	now := i.cfg.Clock.Now()
	return i.mint(ctx, Claims{
		Subject:    s.UPN,
		Issuer:     i.cfg.Issuer,
		Audience:   i.cfg.Audience,
		IssuedAt:   now,
		ExpiresAt:  now.Add(i.cfg.TTL),
		JTI:        uuid.NewString(),
		Groups:     s.Groups,
		Roles:      s.Roles,
		AuthMethod: AuthMethodPassword,
	})
}

// Refresh exchanges a still-valid (signature + revocation) token for a new
// one with refreshed `exp` but unchanged `iat`. Refuses if the refresh
// window has been exhausted, if the token is revoked, or if signature is bad.
func (i *Issuer) Refresh(ctx context.Context, raw string) (*IssuedToken, error) {
	c, err := i.validateInner(ctx, raw, allowExpired)
	if err != nil {
		return nil, err
	}
	now := i.cfg.Clock.Now()
	if now.Sub(c.IssuedAt) > i.cfg.RefreshWindow {
		return nil, ErrRefreshWindowExhausted
	}
	return i.mint(ctx, Claims{
		Subject:    c.Subject,
		Issuer:     i.cfg.Issuer,
		Audience:   i.cfg.Audience,
		IssuedAt:   c.IssuedAt, // preserve original
		ExpiresAt:  now.Add(i.cfg.TTL),
		JTI:        uuid.NewString(),
		Groups:     c.Groups,
		Roles:      c.Roles,
		AuthMethod: c.AuthMethod,
	})
}

// Validate parses, verifies, checks revocation, and rejects expired tokens.
func (i *Issuer) Validate(ctx context.Context, raw string) (*Claims, error) {
	return i.validateInner(ctx, raw, rejectExpired)
}

type expirationMode int

const (
	rejectExpired expirationMode = iota
	allowExpired
)

func (i *Issuer) validateInner(ctx context.Context, raw string, mode expirationMode) (*Claims, error) {
	pub := i.cfg.Signer.PublicKey()
	parsed, err := jwt.Parse([]byte(raw),
		jwt.WithKey(jwa.EdDSA, pub),
		jwt.WithIssuer(i.cfg.Issuer),
		jwt.WithAudience(i.cfg.Audience),
		jwt.WithValidate(false), // we do exp manually so we can implement allowExpired
		jwt.WithVerify(true),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}
	c, err := claimsFromJWT(parsed)
	if err != nil {
		return nil, err
	}
	if mode == rejectExpired && i.cfg.Clock.Now().After(c.ExpiresAt) {
		return nil, ErrExpired
	}
	revoked, err := i.cfg.Store.IsRevoked(ctx, c.JTI)
	if err != nil {
		return nil, fmt.Errorf("check revocation: %w", err)
	}
	if revoked {
		return nil, ErrRevoked
	}
	return c, nil
}

// Revoke records the jti as revoked until its current exp.
func (i *Issuer) Revoke(ctx context.Context, raw, actorUPN, reason string) error {
	c, err := i.validateInner(ctx, raw, allowExpired)
	if err != nil {
		return err
	}
	return i.cfg.Store.Revoke(ctx, c.JTI, actorUPN, reason, c.ExpiresAt)
}

func (i *Issuer) mint(_ context.Context, c Claims) (*IssuedToken, error) {
	t := jwt.New()
	_ = t.Set(jwt.SubjectKey, c.Subject)
	_ = t.Set(jwt.IssuerKey, c.Issuer)
	_ = t.Set(jwt.AudienceKey, c.Audience)
	_ = t.Set(jwt.IssuedAtKey, c.IssuedAt)
	_ = t.Set(jwt.ExpirationKey, c.ExpiresAt)
	_ = t.Set(jwt.JwtIDKey, c.JTI)
	_ = t.Set("groups", c.Groups)
	_ = t.Set("roles", c.Roles)
	_ = t.Set("auth_method", string(c.AuthMethod))

	hdr := jws.NewHeaders()
	_ = hdr.Set(jws.KeyIDKey, i.cfg.Signer.KeyID())
	_ = hdr.Set(jws.TypeKey, "JWT")

	signed, err := jwt.Sign(t,
		jwt.WithKey(jwa.EdDSA, ed25519PrivateAdapter{sig: i.cfg.Signer}, jws.WithProtectedHeaders(hdr)),
	)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	return &IssuedToken{
		AccessToken:         string(signed),
		ExpiresAt:           c.ExpiresAt,
		RefreshWindowEndsAt: c.IssuedAt.Add(i.cfg.RefreshWindow),
		IssuedAt:            c.IssuedAt,
		JTI:                 c.JTI,
	}, nil
}

func claimsFromJWT(t jwt.Token) (*Claims, error) {
	out := &Claims{
		Subject:   t.Subject(),
		Issuer:    t.Issuer(),
		IssuedAt:  t.IssuedAt().UTC(),
		ExpiresAt: t.Expiration().UTC(),
		JTI:       t.JwtID(),
	}
	if aud := t.Audience(); len(aud) > 0 {
		out.Audience = aud[0]
	}
	if v, ok := t.Get("groups"); ok {
		if gs, ok := toStringSlice(v); ok {
			out.Groups = gs
		}
	}
	if v, ok := t.Get("roles"); ok {
		if rs, ok := toStringSlice(v); ok {
			out.Roles = rs
		}
	}
	if v, ok := t.Get("auth_method"); ok {
		if s, ok := v.(string); ok {
			out.AuthMethod = AuthMethod(s)
		}
	}
	if out.Subject == "" || out.JTI == "" || out.IssuedAt.IsZero() || out.ExpiresAt.IsZero() {
		return nil, ErrInvalidClaims
	}
	return out, nil
}

func toStringSlice(v any) ([]string, bool) {
	switch xs := v.(type) {
	case []string:
		return xs, true
	case []any:
		out := make([]string, 0, len(xs))
		for _, x := range xs {
			s, ok := x.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}
	return nil, false
}

// PruneRevocations deletes revoked rows whose exp has passed.
// Run from a goroutine on a ticker (every 5 minutes is typical).
func (i *Issuer) PruneRevocations(ctx context.Context) error {
	_, err := i.cfg.Store.PruneExpired(ctx, i.cfg.Clock.Now())
	return err
}

// ed25519PrivateAdapter lets jwx call our Signer without exposing the raw private key.
type ed25519PrivateAdapter struct{ sig signer.Signer }

func (a ed25519PrivateAdapter) Public() crypto.PublicKey { return a.sig.PublicKey() }

func (a ed25519PrivateAdapter) Sign(_ io.Reader, msg []byte, _ crypto.SignerOpts) ([]byte, error) {
	return a.sig.Sign(msg)
}
