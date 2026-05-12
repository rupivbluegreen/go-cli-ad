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

package signer_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/signer"
)

func writeKey(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.ed25519")
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: priv.Seed()}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestFileSignerRoundTrip(t *testing.T) {
	path := writeKey(t)
	s, err := signer.NewFileSigner(path, "kid-1")
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	msg := []byte("hello")
	sig, err := s.Sign(msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !ed25519.Verify(s.PublicKey(), msg, sig) {
		t.Fatalf("verify failed")
	}
	if s.KeyID() != "kid-1" {
		t.Fatalf("kid = %q", s.KeyID())
	}
}

func TestFileSignerRejectsBadPermissions(t *testing.T) {
	path := writeKey(t)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := signer.NewFileSigner(path, "kid-1"); err == nil {
		t.Fatalf("want error for non-0600 key")
	}
}
