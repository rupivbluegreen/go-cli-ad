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

// ADFSProvider is the Phase 2 seam. All methods return ErrNotImplemented.
type ADFSProvider struct{}

func (ADFSProvider) Authenticate(_ context.Context, _, _ string) (*Identity, error) {
	return nil, ErrNotImplemented
}
func (ADFSProvider) InitiateChallenge(_ context.Context, _ string) (*Challenge, error) {
	return nil, ErrNotImplemented
}
func (ADFSProvider) CompleteChallenge(_ context.Context, _ string) (*Identity, error) {
	return nil, ErrNotImplemented
}
func (ADFSProvider) Lookup(_ context.Context, _ string) (*Identity, error) {
	return nil, ErrNotImplemented
}
func (ADFSProvider) HealthCheck(_ context.Context) error { return ErrNotImplemented }
func (ADFSProvider) Capabilities() ProviderCapabilities  { return ProviderCapabilities{} }
