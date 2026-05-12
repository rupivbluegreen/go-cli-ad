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
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// NewRouter returns a fully wired chi router for the broker. Middleware order:
// RequestID -> Recover -> AccessLog -> RateLimit.PerIP -> route-level handlers.
func NewRouter(d *Deps, logger *slog.Logger) http.Handler {
	r := chi.NewRouter()
	r.Use(RequestID)
	r.Use(Recover)
	r.Use(AccessLog(logger))
	r.Use(d.RateLimiter.PerIP)

	r.Post("/v1/auth/token", HandleTokenIssue(d))
	r.Post("/v1/auth/refresh", HandleTokenRefresh(d))
	r.Post("/v1/auth/logout", HandleLogout(d))
	r.Get("/v1/me", HandleMe(d))
	r.Get("/v1/.well-known/jwks.json", HandleJWKS(d))
	r.Get("/healthz", HandleHealthz())
	r.Get("/readyz", HandleReadyz(d))
	r.Handle("/metrics", promhttp.Handler())
	return r
}
