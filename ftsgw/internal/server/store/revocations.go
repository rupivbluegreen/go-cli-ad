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

// Revoke inserts (or replaces) a revocation entry for jti.
func (s *Store) Revoke(ctx context.Context, jti, actorUPN, reason string, exp time.Time) error {
	_, err := s.DB.ExecContext(ctx,
		`INSERT OR REPLACE INTO revoked_tokens (jti, revoked_at, exp, actor_upn, reason) VALUES (?, ?, ?, ?, ?)`,
		jti, time.Now().UTC(), exp.UTC(), actorUPN, nullableReason(reason))
	if err != nil {
		return fmt.Errorf("revoke %s: %w", jti, err)
	}
	return nil
}

// IsRevoked returns whether jti has been revoked.
func (s *Store) IsRevoked(ctx context.Context, jti string) (bool, error) {
	var n int
	err := s.DB.QueryRowContext(ctx, `SELECT 1 FROM revoked_tokens WHERE jti = ?`, jti).Scan(&n)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("is_revoked %s: %w", jti, err)
	}
	return true, nil
}

// PruneExpired deletes rows whose exp is at or before cutoff. Returns count.
func (s *Store) PruneExpired(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM revoked_tokens WHERE exp <= ?`, cutoff.UTC())
	if err != nil {
		return 0, fmt.Errorf("prune: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

func nullableReason(s string) any {
	if s == "" {
		return nil
	}
	return s
}
