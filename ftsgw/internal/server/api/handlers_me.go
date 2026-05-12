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
	"net/http"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/pkg/api/types"
)

// HandleMe returns identity + group list for the current bearer token.
func HandleMe(d *Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, _, err := authnFromBearer(d, r)
		if err != nil {
			WriteProblem(w, HTTPStatusFor(err), "Unauthorized", err.Error(), RequestIDFrom(r.Context()))
			return
		}
		body := types.MeResponse{
			UPN:            claims.Subject,
			DisplayName:    claims.Subject, // Phase 0: we don't re-resolve display name
			Groups:         claims.Groups,
			Roles:          claims.Roles,
			TokenIssuedAt:  claims.IssuedAt,
			TokenExpiresAt: claims.ExpiresAt,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(body)
	}
}
