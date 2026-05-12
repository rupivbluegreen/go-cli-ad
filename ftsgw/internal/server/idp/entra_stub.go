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

import "context"

// EntraProvider is the Phase 1 seam. All methods return ErrNotImplemented.
type EntraProvider struct{}

func (EntraProvider) Authenticate(_ context.Context, _, _ string) (*Identity, error) {
	return nil, ErrNotImplemented
}
func (EntraProvider) InitiateChallenge(_ context.Context, _ string) (*Challenge, error) {
	return nil, ErrNotImplemented
}
func (EntraProvider) CompleteChallenge(_ context.Context, _ string) (*Identity, error) {
	return nil, ErrNotImplemented
}
func (EntraProvider) Lookup(_ context.Context, _ string) (*Identity, error) {
	return nil, ErrNotImplemented
}
func (EntraProvider) HealthCheck(_ context.Context) error { return ErrNotImplemented }
func (EntraProvider) Capabilities() ProviderCapabilities  { return ProviderCapabilities{} }
