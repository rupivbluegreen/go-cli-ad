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

// Package idp abstracts the user-store backend. Phase 0 ships LDAPProvider;
// Phase 1 will add Entra (device-code challenge); Phase 2 will add ADFS.
// New methods may NEVER be added to IdentityProvider — the Challenge methods
// already exist precisely so we never break this interface.
package idp

import (
	"context"
	"time"
)

// Identity is the resolved user view used by token issuance.
type Identity struct {
	UPN         string
	DisplayName string
	Groups      []string
	Roles       []string
	Attributes  map[string]string
}

// Challenge is the device-code / out-of-band challenge handle returned by
// providers that implement multi-step auth (Phase 1+).
type Challenge struct {
	ID              string
	UserCode        string
	VerificationURI string
	ExpiresIn       time.Duration
	Interval        time.Duration
}

// ProviderCapabilities advertises which Authenticate paths a provider implements.
type ProviderCapabilities struct {
	SupportsPassword  bool
	SupportsChallenge bool
}

// IdentityProvider is the seam between the broker and any backing store.
type IdentityProvider interface {
	Authenticate(ctx context.Context, username, password string) (*Identity, error)
	InitiateChallenge(ctx context.Context, hint string) (*Challenge, error)
	CompleteChallenge(ctx context.Context, challengeID string) (*Identity, error)
	Lookup(ctx context.Context, upn string) (*Identity, error)
	HealthCheck(ctx context.Context) error
	Capabilities() ProviderCapabilities
}
