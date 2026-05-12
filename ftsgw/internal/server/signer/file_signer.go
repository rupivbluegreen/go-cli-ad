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

import (
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"runtime"
)

// FileSigner loads an Ed25519 seed from a PEM file with mode 0600.
type FileSigner struct {
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	keyID string
}

// NewFileSigner reads the key from path and verifies its file permissions.
func NewFileSigner(path, keyID string) (*FileSigner, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat signing key: %w", err)
	}
	// Windows uses ACLs, not POSIX mode bits, so os.Chmod cannot produce 0600
	// there. Skip the check on Windows; operators secure the key via NTFS ACLs.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("signing key %s must be mode 0600, got %o", path, info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("signing key: invalid PEM")
	}
	if len(block.Bytes) != ed25519.SeedSize {
		return nil, fmt.Errorf("signing key: expected %d-byte seed, got %d", ed25519.SeedSize, len(block.Bytes))
	}
	priv := ed25519.NewKeyFromSeed(block.Bytes)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("signing key: failed to derive public key")
	}
	return &FileSigner{priv: priv, pub: pub, keyID: keyID}, nil
}

// Sign returns an Ed25519 signature over msg.
func (s *FileSigner) Sign(msg []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, msg), nil
}

// PublicKey returns the verification key for JWKS publication.
func (s *FileSigner) PublicKey() ed25519.PublicKey { return s.pub }

// KeyID returns the JWT `kid` value.
func (s *FileSigner) KeyID() string { return s.keyID }
