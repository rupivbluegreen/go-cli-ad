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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	HTTPRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ftsgw_http_requests_total",
		Help: "HTTP requests by route and status.",
	}, []string{"route", "status"})

	HTTPDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ftsgw_http_request_duration_seconds",
		Help:    "HTTP request duration by route.",
		Buckets: prometheus.DefBuckets,
	}, []string{"route"})

	PasswordAuthTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ftsgw_password_auth_total",
		Help: "Password authentications by outcome.",
	}, []string{"outcome"})

	TokensIssuedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ftsgw_tokens_issued_total", Help: "Tokens minted.",
	})

	TokensRefreshedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ftsgw_tokens_refreshed_total", Help: "Tokens refreshed.",
	})

	TokensRefreshRefusedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ftsgw_tokens_refresh_refused_total", Help: "Refresh refusals by reason.",
	}, []string{"reason"})

	TokensRevokedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ftsgw_tokens_revoked_total", Help: "Tokens explicitly revoked.",
	})

	IdPAuthDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "ftsgw_idp_auth_duration_seconds", Help: "IdP authenticate latency.",
		Buckets: prometheus.DefBuckets,
	}, []string{"idp"})

	AuditWriteFailuresTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ftsgw_audit_write_failures_total", Help: "Audit sink write failures.",
	})

	RateLimitedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ftsgw_rate_limited_total", Help: "Rate-limit denials by endpoint.",
	}, []string{"endpoint"})
)
