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

package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/store"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Logger implements LogWriter against a SQLite Store + a rotated JSON-lines file.
type Logger struct {
	mu   sync.Mutex
	file io.WriteCloser
	st   *store.Store
	rng  *ulid.MonotonicEntropy
}

// NewLogger opens (creates) the rotated file at logPath with 100MB segments
// and 30-day retention and ties it to the provided Store.
func NewLogger(logPath string, st *store.Store) (*Logger, error) {
	f := &lumberjack.Logger{
		Filename:   logPath,
		MaxSize:    100, // MB
		MaxAge:     30,  // days
		MaxBackups: 30,
		Compress:   true,
		LocalTime:  false,
	}
	return &Logger{
		file: f,
		st:   st,
		rng:  ulid.Monotonic(ulidRandReader(), 0),
	}, nil
}

// Write emits one event to both sinks. The DB write happens first so
// truncated-file conditions still leave a database trace; either failure
// is returned and the caller MUST surface HTTP 503.
func (l *Logger) Write(ctx context.Context, e Event) error {
	for k := range e.Extras {
		if _, bad := forbiddenKeys[k]; bad {
			return fmt.Errorf("%w: %q", ErrForbiddenAuditKey, k)
		}
	}
	if e.TS.IsZero() {
		e.TS = time.Now().UTC()
	}
	id := ulid.MustNew(ulid.Timestamp(e.TS), l.rng).String()
	payload := map[string]any{
		"ts":         e.TS.Format(time.RFC3339Nano),
		"request_id": e.RequestID,
		"actor_upn":  nullable(e.ActorUPN),
		"event":      string(e.Event),
		"outcome":    e.Outcome,
		"reason":     nullable(e.Reason),
		"client_ip":  nullable(e.ClientIP),
		"trace_id":   nullable(e.TraceID),
		"extras":     e.Extras,
	}
	pj, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal audit: %w", err)
	}
	if err := l.st.WriteEvent(ctx, store.EventRow{
		ID:          id,
		TS:          e.TS,
		ActorUPN:    e.ActorUPN,
		EventType:   string(e.Event),
		Outcome:     e.Outcome,
		Reason:      e.Reason,
		ClientIP:    e.ClientIP,
		RequestID:   e.RequestID,
		TraceID:     e.TraceID,
		PayloadJSON: string(pj),
	}); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.file.Write(append(pj, '\n')); err != nil {
		return fmt.Errorf("write audit file: %w", err)
	}
	return nil
}

// Close flushes and closes the rotated file. The Store is owned by the caller.
func (l *Logger) Close() error { return l.file.Close() }

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
