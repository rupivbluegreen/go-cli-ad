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

package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
)

type ctxKey int

const (
	ctxKeyRequestID ctxKey = iota
	ctxKeyActorUPN
)

// RequestID injects/propagates a request ID, mirroring it to the response.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if id == "" {
			id = uuid.NewString()
		}
		w.Header().Set("X-Request-Id", id)
		ctx := context.WithValue(r.Context(), ctxKeyRequestID, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequestIDFrom returns the injected request ID, "" if absent.
func RequestIDFrom(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeyRequestID).(string)
	return v
}

// ActorUPNFrom returns the authenticated UPN set by Authn, "" if anonymous.
func ActorUPNFrom(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeyActorUPN).(string)
	return v
}

// WithActorUPN attaches an actor UPN to the context (used by Authn middleware).
func WithActorUPN(ctx context.Context, upn string) context.Context {
	return context.WithValue(ctx, ctxKeyActorUPN, upn)
}

// AccessLog emits one slog Info per request after it completes.
func AccessLog(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusRecorder{ResponseWriter: w, status: 200}
			next.ServeHTTP(sw, r)
			logger.Info("http_request",
				"request_id", RequestIDFrom(r.Context()),
				"method", r.Method,
				"path", r.URL.Path,
				"status", sw.status,
				"duration_ms", time.Since(start).Milliseconds(),
				"actor_upn", ActorUPNFrom(r.Context()),
			)
		})
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Recover converts panics into HTTP 500 problem responses.
func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				WriteProblem(w, http.StatusInternalServerError, "Internal Error", "panic", RequestIDFrom(r.Context()))
			}
		}()
		next.ServeHTTP(w, r)
	})
}
