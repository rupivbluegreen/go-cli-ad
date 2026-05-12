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

package api_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/api"
)

func TestPerIPLimiterTriggers429(t *testing.T) {
	rl := api.NewRateLimiter(api.RateLimits{PerIPRPS: 1, PerIPBurst: 1, AuthPerUsernamePerMinute: 60})
	h := rl.PerIP(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(204)
	}))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	first := httptest.NewRecorder()
	h.ServeHTTP(first, r)
	second := httptest.NewRecorder()
	h.ServeHTTP(second, r)
	if first.Code == 429 || second.Code != 429 {
		t.Fatalf("first=%d second=%d", first.Code, second.Code)
	}
}

func TestPerUsernameLimiterTriggers429(t *testing.T) {
	rl := api.NewRateLimiter(api.RateLimits{PerIPRPS: 1000, PerIPBurst: 1000, AuthPerUsernamePerMinute: 2})
	rl.Clock = func() time.Time { return time.Date(2026, 5, 7, 14, 0, 0, 0, time.UTC) }
	for i := 0; i < 2; i++ {
		if !rl.AllowAuth("alice") {
			t.Fatalf("attempt %d should pass", i+1)
		}
	}
	if rl.AllowAuth("alice") {
		t.Fatalf("third attempt should be limited")
	}
}
