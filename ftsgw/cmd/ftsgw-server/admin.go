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

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/config"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/store"
)

// runRevoke implements `ftsgw-server revoke --jti=... --reason=...`.
func runRevoke(args []string) int {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/ftsgw-server/config.yaml", "config path")
	jti := fs.String("jti", "", "JTI to revoke")
	reason := fs.String("reason", "admin-revoke", "reason recorded in audit/store")
	actor := fs.String("actor", "admin", "actor UPN recorded")
	exp := fs.Duration("exp-from-now", 24*time.Hour, "how far in the future to set exp (cleanup horizon)")
	_ = fs.Parse(args)
	if *jti == "" {
		fmt.Fprintln(os.Stderr, "revoke: --jti required")
		return 2
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 1
	}
	st, err := store.Open(filepath.Join(filepath.Dir(cfg.Audit.FilePath), "ftsgw.db"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "store:", err)
		return 1
	}
	defer func() { _ = st.Close() }()
	if err := st.Revoke(context.Background(), *jti, *actor, *reason, time.Now().Add(*exp).UTC()); err != nil {
		fmt.Fprintln(os.Stderr, "revoke:", err)
		return 1
	}
	fmt.Println("revoked", *jti)
	return 0
}

// runRotateKey generates a new Ed25519 keypair at --out (mode 0600).
func runRotateKey(args []string) int {
	fs := flag.NewFlagSet("rotate-key", flag.ExitOnError)
	out := fs.String("out", "", "output path for new private key")
	_ = fs.Parse(args)
	if *out == "" {
		fmt.Fprintln(os.Stderr, "rotate-key: --out required")
		return 2
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, "genkey:", err)
		return 1
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: priv.Seed()}
	if err := os.WriteFile(*out, pem.EncodeToMemory(block), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		return 1
	}
	fmt.Println("wrote", *out)
	return 0
}
