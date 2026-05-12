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
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/api"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/idp"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/pkg/api/types"
)

func TestWriteProblemUsesProblemJSON(t *testing.T) {
	rr := httptest.NewRecorder()
	api.WriteProblem(rr, http.StatusUnauthorized, "Authentication failed", "bad password", "req-1")
	if rr.Header().Get("Content-Type") != types.ProblemContentType {
		t.Fatalf("content-type = %q", rr.Header().Get("Content-Type"))
	}
	var pd types.ProblemDetails
	_ = json.Unmarshal(rr.Body.Bytes(), &pd)
	if pd.Status != http.StatusUnauthorized || pd.RequestID != "req-1" {
		t.Fatalf("body = %+v", pd)
	}
}

func TestMapIdPError(t *testing.T) {
	if s := api.HTTPStatusFor(idp.ErrAuth); s != http.StatusUnauthorized {
		t.Fatalf("ErrAuth -> %d", s)
	}
	if s := api.HTTPStatusFor(idp.ErrUnreachable); s != http.StatusBadGateway {
		t.Fatalf("ErrUnreachable -> %d", s)
	}
	if s := api.HTTPStatusFor(errors.New("other")); s != http.StatusInternalServerError {
		t.Fatalf("default -> %d", s)
	}
}
