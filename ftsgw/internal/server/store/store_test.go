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

package store_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/store"
)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ftsgw.db")
	s, err := store.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestRevokeAndCheck(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	exp := time.Now().Add(15 * time.Minute).UTC()
	if err := s.Revoke(ctx, "jti-1", "alice@example", "logout", exp); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	got, err := s.IsRevoked(ctx, "jti-1")
	if err != nil || !got {
		t.Fatalf("IsRevoked = %v, err = %v", got, err)
	}
	got, _ = s.IsRevoked(ctx, "jti-other")
	if got {
		t.Fatalf("unexpected revoked")
	}
}

func TestPruneExpired(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	past := time.Now().Add(-time.Minute).UTC()
	future := time.Now().Add(time.Hour).UTC()
	_ = s.Revoke(ctx, "jti-old", "a", "", past)
	_ = s.Revoke(ctx, "jti-new", "b", "", future)
	n, err := s.PruneExpired(ctx, time.Now().UTC())
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Fatalf("pruned %d, want 1", n)
	}
	got, _ := s.IsRevoked(ctx, "jti-new")
	if !got {
		t.Fatalf("new entry should remain")
	}
}

func TestWriteEvent(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	err := s.WriteEvent(ctx, store.EventRow{
		ID:          "01HXY",
		TS:          time.Now().UTC(),
		ActorUPN:    "alice@example",
		EventType:   "token_issued",
		Outcome:     "success",
		RequestID:   "req-1",
		PayloadJSON: `{"jti":"x"}`,
	})
	if err != nil {
		t.Fatalf("write: %v", err)
	}
}
