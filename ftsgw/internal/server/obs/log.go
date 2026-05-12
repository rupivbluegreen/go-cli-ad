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

// Package obs houses observability glue: structured logging with a redacting
// handler, and OpenTelemetry setup.
package obs

import (
	"context"
	"log/slog"
	"strings"
)

// RedactingHandler wraps an inner slog.Handler and replaces values of attrs
// whose key matches the secret deny-list with "***REDACTED***".
type RedactingHandler struct{ inner slog.Handler }

// NewRedactingHandler returns a Handler that redacts secret-shaped attrs.
func NewRedactingHandler(inner slog.Handler) *RedactingHandler {
	return &RedactingHandler{inner: inner}
}

// Enabled delegates.
func (h *RedactingHandler) Enabled(ctx context.Context, lvl slog.Level) bool {
	return h.inner.Enabled(ctx, lvl)
}

// Handle redacts and delegates.
func (h *RedactingHandler) Handle(ctx context.Context, r slog.Record) error {
	r2 := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		r2.AddAttrs(redact(a))
		return true
	})
	return h.inner.Handle(ctx, r2)
}

// WithAttrs delegates while keeping redaction.
func (h *RedactingHandler) WithAttrs(as []slog.Attr) slog.Handler {
	cleaned := make([]slog.Attr, 0, len(as))
	for _, a := range as {
		cleaned = append(cleaned, redact(a))
	}
	return &RedactingHandler{inner: h.inner.WithAttrs(cleaned)}
}

// WithGroup delegates.
func (h *RedactingHandler) WithGroup(name string) slog.Handler {
	return &RedactingHandler{inner: h.inner.WithGroup(name)}
}

var secretKeys = []string{"password", "authorization", "access_token", "token", "secret", "bearer"}

func redact(a slog.Attr) slog.Attr {
	k := strings.ToLower(a.Key)
	for _, s := range secretKeys {
		if k == s {
			return slog.Attr{Key: a.Key, Value: slog.StringValue("***REDACTED***")}
		}
	}
	return a
}
