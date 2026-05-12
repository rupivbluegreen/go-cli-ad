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
	"fmt"
	"time"
)

// EventRow is the on-disk shape of one audit event.
type EventRow struct {
	ID          string
	TS          time.Time
	ActorUPN    string
	EventType   string
	Outcome     string
	Reason      string
	ClientIP    string
	RequestID   string
	TraceID     string
	PayloadJSON string
}

// WriteEvent inserts a single audit row. Failure must surface (the audit
// path treats this as a 503 trigger).
func (s *Store) WriteEvent(ctx context.Context, r EventRow) error {
	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO audit_events (id, ts, actor_upn, event_type, outcome, reason, client_ip, request_id, trace_id, payload_json)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.TS.UTC(), nullableReason(r.ActorUPN), r.EventType, r.Outcome,
		nullableReason(r.Reason), nullableReason(r.ClientIP), r.RequestID,
		nullableReason(r.TraceID), r.PayloadJSON)
	if err != nil {
		return fmt.Errorf("write event %s: %w", r.ID, err)
	}
	return nil
}
