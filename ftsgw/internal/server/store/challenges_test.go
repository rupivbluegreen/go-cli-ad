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
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/store"
)

func openChallengeStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "ch.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestCreateAndGetChallenge(t *testing.T) {
	s := openChallengeStore(t)
	ctx := context.Background()
	now := time.Date(2026, 5, 7, 14, 0, 0, 0, time.UTC)
	in := store.PendingChallenge{
		ID:              "ch-1",
		UserHint:        "alice@example.com",
		DeviceCode:      "DC123",
		UserCode:        "ABCD-1234",
		VerificationURI: "https://login.microsoftonline.com/common/oauth2/deviceauth",
		IntervalSeconds: 5,
		ExpiresAt:       now.Add(15 * time.Minute),
		CreatedAt:       now,
	}
	if err := s.CreateChallenge(ctx, in); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.GetChallenge(ctx, "ch-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ID != in.ID || got.UserCode != in.UserCode || got.State != "pending" {
		t.Fatalf("mismatch: %+v", got)
	}
}

func TestGetMissingChallenge(t *testing.T) {
	s := openChallengeStore(t)
	_, err := s.GetChallenge(context.Background(), "absent")
	if !errors.Is(err, store.ErrChallengeNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestMarkChallengeCompletedIdempotent(t *testing.T) {
	s := openChallengeStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_ = s.CreateChallenge(ctx, store.PendingChallenge{
		ID: "ch-2", DeviceCode: "x", UserCode: "y", VerificationURI: "z",
		IntervalSeconds: 5, ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	})
	// First mark wins.
	if err := s.MarkChallengeCompleted(ctx, "ch-2"); err != nil {
		t.Fatalf("first mark: %v", err)
	}
	// Second mark returns ErrChallengeNotFound (no pending row to update).
	if err := s.MarkChallengeCompleted(ctx, "ch-2"); !errors.Is(err, store.ErrChallengeNotFound) {
		t.Fatalf("second mark should refuse: %v", err)
	}
}

func TestPruneExpiredChallenges(t *testing.T) {
	s := openChallengeStore(t)
	ctx := context.Background()
	past := time.Now().Add(-time.Minute).UTC()
	future := time.Now().Add(time.Hour).UTC()
	for i, exp := range []time.Time{past, future} {
		_ = s.CreateChallenge(ctx, store.PendingChallenge{
			ID:              "ch-" + string(rune('a'+i)),
			DeviceCode:      "d",
			UserCode:        "u",
			VerificationURI: "v",
			IntervalSeconds: 5,
			ExpiresAt:       exp,
			CreatedAt:       time.Now().UTC(),
		})
	}
	n, err := s.PruneExpiredChallenges(ctx, time.Now().UTC())
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Fatalf("pruned %d, want 1", n)
	}
}

func TestDeleteChallenge(t *testing.T) {
	s := openChallengeStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_ = s.CreateChallenge(ctx, store.PendingChallenge{
		ID: "ch-d", DeviceCode: "d", UserCode: "u", VerificationURI: "v",
		IntervalSeconds: 5, ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	})
	if err := s.DeleteChallenge(ctx, "ch-d"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.GetChallenge(ctx, "ch-d"); !errors.Is(err, store.ErrChallengeNotFound) {
		t.Fatalf("expected not-found after delete: %v", err)
	}
}
