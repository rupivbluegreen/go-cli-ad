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
	"encoding/json"
	"net/http"
	"time"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/pkg/api/types"
)

// HandleHealthz returns 200 if the process is running. No external checks.
func HandleHealthz() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(types.HealthResponse{Status: "ok", Checks: map[string]types.HealthCheck{}})
	}
}

// HandleReadyz pings the IdP. 200 only when ready to serve.
func HandleReadyz(d *Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		status := "ok"
		check := types.HealthCheck{Status: "ok"}
		if err := d.IdP.HealthCheck(ctx); err != nil {
			status = "degraded"
			check = types.HealthCheck{Status: "fail", Detail: err.Error()}
		}
		w.Header().Set("Content-Type", "application/json")
		code := http.StatusOK
		if status != "ok" {
			code = http.StatusServiceUnavailable
		}
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(types.HealthResponse{
			Status: status, Checks: map[string]types.HealthCheck{"idp": check},
		})
	}
}
