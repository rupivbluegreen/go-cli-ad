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

// Package audit writes one event to two sinks: the SQLite audit_events
// table and a rotated JSON-lines file. Both writes happen synchronously;
// any failure surfaces to the caller so the broker can return HTTP 503.
//
// Secrets MUST NEVER appear in audit payloads. The Logger enforces this
// statically (forbidden Extras keys) and operators must enforce it by
// review when adding new fields.
package audit

import (
	"context"
	"errors"
	"time"
)

// Event is the in-memory shape of an audit record.
type Event struct {
	TS        time.Time
	RequestID string
	ActorUPN  string
	Event     EventType
	Outcome   string // "success" | "failure"
	Reason    string
	ClientIP  string
	TraceID   string
	Extras    map[string]any
}

// ErrForbiddenAuditKey is returned when Extras contains a key from the deny list.
var ErrForbiddenAuditKey = errors.New("audit: forbidden key in extras")

// forbiddenKeys lists Extras names that may carry secrets. The set is
// intentionally tight; widen with care.
var forbiddenKeys = map[string]struct{}{
	"password":     {},
	"access_token": {},
	"token":        {},
	"secret":       {},
	"bearer":       {},
}

// LogWriter is the sink interface (file + DB).
type LogWriter interface {
	Write(ctx context.Context, e Event) error
	Close() error
}
