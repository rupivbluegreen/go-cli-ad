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

package signer

import "crypto/ed25519"

// StubHSMSigner is the Phase-2 seam for a hardware-backed Ed25519 key. All
// calls return ErrNotImplemented so the broker fails fast if misconfigured.
type StubHSMSigner struct{}

func (StubHSMSigner) Sign(_ []byte) ([]byte, error)   { return nil, ErrNotImplemented }
func (StubHSMSigner) PublicKey() ed25519.PublicKey    { return nil }
func (StubHSMSigner) KeyID() string                   { return "" }
