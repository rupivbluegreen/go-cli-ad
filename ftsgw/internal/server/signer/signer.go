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

// Package signer mints Ed25519 signatures for ftsgw JWTs. The Signer
// interface is the seam: FileSigner is shipped today; StubHSMSigner is the
// integration seam for a hardware-backed key in a future phase.
package signer

import (
	"crypto/ed25519"
	"errors"
)

// ErrNotImplemented is returned by stubs.
var ErrNotImplemented = errors.New("signer: not implemented")

// Signer is the minting interface used by the auth package.
type Signer interface {
	Sign(msg []byte) ([]byte, error)
	PublicKey() ed25519.PublicKey
	KeyID() string
}
