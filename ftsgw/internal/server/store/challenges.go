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

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// PendingChallenge is the in-flight device-code challenge row.
type PendingChallenge struct {
	ID              string
	UserHint        string
	DeviceCode      string
	UserCode        string
	VerificationURI string
	IntervalSeconds int
	ExpiresAt       time.Time
	CreatedAt       time.Time
	State           string // "pending" | "completed" | "expired"
}

// ErrChallengeNotFound is returned when a lookup misses.
var ErrChallengeNotFound = errors.New("store: challenge not found")

// CreateChallenge inserts a new pending challenge row.
func (s *Store) CreateChallenge(ctx context.Context, c PendingChallenge) error {
	if c.State == "" {
		c.State = "pending"
	}
	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO pending_challenges
		   (id, user_hint, device_code, user_code, verification_uri, interval_seconds, expires_at, created_at, state)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, nullableReason(c.UserHint), c.DeviceCode, c.UserCode, c.VerificationURI,
		c.IntervalSeconds, c.ExpiresAt.UTC(), c.CreatedAt.UTC(), c.State)
	if err != nil {
		return fmt.Errorf("create challenge %s: %w", c.ID, err)
	}
	return nil
}

// GetChallenge fetches a pending challenge by ID.
func (s *Store) GetChallenge(ctx context.Context, id string) (*PendingChallenge, error) {
	row := s.DB.QueryRowContext(ctx,
		`SELECT id, COALESCE(user_hint, ''), device_code, user_code, verification_uri,
		        interval_seconds, expires_at, created_at, state
		   FROM pending_challenges WHERE id = ?`, id)
	var c PendingChallenge
	if err := row.Scan(&c.ID, &c.UserHint, &c.DeviceCode, &c.UserCode, &c.VerificationURI,
		&c.IntervalSeconds, &c.ExpiresAt, &c.CreatedAt, &c.State); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrChallengeNotFound
		}
		return nil, fmt.Errorf("get challenge %s: %w", id, err)
	}
	return &c, nil
}

// MarkChallengeCompleted transitions a pending challenge to "completed".
// Returns ErrChallengeNotFound if no pending row matches (idempotent guard
// against concurrent polls double-minting tokens).
func (s *Store) MarkChallengeCompleted(ctx context.Context, id string) error {
	res, err := s.DB.ExecContext(ctx,
		`UPDATE pending_challenges SET state = 'completed' WHERE id = ? AND state = 'pending'`, id)
	if err != nil {
		return fmt.Errorf("mark completed %s: %w", id, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrChallengeNotFound
	}
	return nil
}

// DeleteChallenge removes a challenge row by ID.
func (s *Store) DeleteChallenge(ctx context.Context, id string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM pending_challenges WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete challenge %s: %w", id, err)
	}
	return nil
}

// PruneExpiredChallenges deletes rows whose expires_at is at or before cutoff.
func (s *Store) PruneExpiredChallenges(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.DB.ExecContext(ctx,
		`DELETE FROM pending_challenges WHERE expires_at <= ?`, cutoff.UTC())
	if err != nil {
		return 0, fmt.Errorf("prune challenges: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
