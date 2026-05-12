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
	"encoding/json"
	"errors"
	"net/http"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/auth"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/idp"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/pkg/api/types"
)

// WriteProblem emits a Content-Type: application/problem+json response.
func WriteProblem(w http.ResponseWriter, status int, title, detail, requestID string) {
	body := types.ProblemDetails{
		Type:      "about:blank",
		Title:     title,
		Status:    status,
		Detail:    detail,
		RequestID: requestID,
	}
	w.Header().Set("Content-Type", types.ProblemContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// HTTPStatusFor maps known sentinels to HTTP status codes; unknown errors -> 500.
func HTTPStatusFor(err error) int {
	switch {
	case errors.Is(err, idp.ErrAuth):
		return http.StatusUnauthorized
	case errors.Is(err, idp.ErrUnreachable):
		return http.StatusBadGateway
	case errors.Is(err, idp.ErrNotImplemented), errors.Is(err, idp.ErrNotSupported):
		return http.StatusNotImplemented
	case errors.Is(err, auth.ErrExpired), errors.Is(err, auth.ErrRevoked), errors.Is(err, auth.ErrInvalidSignature):
		return http.StatusUnauthorized
	case errors.Is(err, auth.ErrRefreshWindowExhausted):
		return http.StatusUnauthorized
	default:
		return http.StatusInternalServerError
	}
}
