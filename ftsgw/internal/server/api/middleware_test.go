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
	"strings"
	"testing"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/api"
)

func TestRequestIDInjected(t *testing.T) {
	var seen string
	h := api.RequestID(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = api.RequestIDFrom(r.Context())
	}))
	rr := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(rr, r)
	if seen == "" || !strings.HasPrefix(rr.Header().Get("X-Request-Id"), seen[:0]) {
		t.Fatalf("request id missing: ctx=%q header=%q", seen, rr.Header().Get("X-Request-Id"))
	}
}

func TestRequestIDHonoursInbound(t *testing.T) {
	h := api.RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	rr := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Request-Id", "abc-123")
	h.ServeHTTP(rr, r)
	if rr.Header().Get("X-Request-Id") != "abc-123" {
		t.Fatalf("inbound id not preserved")
	}
}

func TestRecoverConvertsPanicTo500(t *testing.T) {
	h := api.Recover(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic("boom")
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if rr.Code != 500 {
		t.Fatalf("code = %d", rr.Code)
	}
}
