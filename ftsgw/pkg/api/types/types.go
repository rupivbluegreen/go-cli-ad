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

// Package types defines the wire types shared by ftsgw-server handlers and
// the ftsgw-cli HTTP client. Anything that crosses the broker boundary
// MUST be defined here and only here.
package types

import "time"

// ProblemContentType is the IANA media type for RFC 7807 problem responses.
const ProblemContentType = "application/problem+json"

// TokenRequest is the body of POST /v1/auth/token.
type TokenRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// TokenResponse is returned by POST /v1/auth/token and /v1/auth/refresh.
type TokenResponse struct {
	AccessToken         string    `json:"access_token"`
	TokenType           string    `json:"token_type"`
	ExpiresAt           time.Time `json:"expires_at"`
	RefreshWindowEndsAt time.Time `json:"refresh_window_ends_at"`
}

// MeResponse is returned by GET /v1/me.
type MeResponse struct {
	UPN             string    `json:"upn"`
	DisplayName     string    `json:"display_name"`
	Groups          []string  `json:"groups"`
	Roles           []string  `json:"roles"`
	TokenIssuedAt   time.Time `json:"token_issued_at"`
	TokenExpiresAt  time.Time `json:"token_expires_at"`
}

// HealthCheck is one component result inside HealthResponse.
type HealthCheck struct {
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// HealthResponse is returned by /healthz and /readyz.
type HealthResponse struct {
	Status string                 `json:"status"`
	Checks map[string]HealthCheck `json:"checks"`
}

// ProblemDetails implements RFC 7807. All error responses MUST use this.
type ProblemDetails struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`
	// RequestID is non-standard but operationally essential.
	RequestID string `json:"request_id,omitempty"`
}
