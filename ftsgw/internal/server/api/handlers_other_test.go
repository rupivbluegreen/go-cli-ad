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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/api"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/auth"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/idp"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/pkg/api/types"
)

func TestMeReturnsClaims(t *testing.T) {
	deps, iss := mkBrokerDeps(t, stubIdP{id: &idp.Identity{UPN: "alice@example", Groups: []string{"g1"}}})
	tok, _ := iss.Mint(context.Background(), auth.Subject{UPN: "alice@example", Groups: []string{"g1"}})
	r := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	r.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	rr := httptest.NewRecorder()
	api.HandleMe(deps).ServeHTTP(rr, r)
	if rr.Code != 200 {
		t.Fatalf("code = %d body=%s", rr.Code, rr.Body.String())
	}
	var me types.MeResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &me)
	if me.UPN != "alice@example" || len(me.Groups) != 1 {
		t.Fatalf("body = %+v", me)
	}
}

func TestHealthzAlwaysOK(t *testing.T) {
	rr := httptest.NewRecorder()
	api.HandleHealthz().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != 200 {
		t.Fatalf("code = %d", rr.Code)
	}
}

func TestJWKSReturnsEdDSAKey(t *testing.T) {
	deps, _ := mkBrokerDeps(t, stubIdP{})
	rr := httptest.NewRecorder()
	api.HandleJWKS(deps).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/.well-known/jwks.json", nil))
	if rr.Code != 200 {
		t.Fatalf("code = %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"kty":"OKP"`) || !strings.Contains(body, `"crv":"Ed25519"`) {
		t.Fatalf("jwks body missing OKP/Ed25519: %s", body)
	}
}
