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

package types_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/pkg/api/types"
)

func TestTokenResponseJSONRoundtrip(t *testing.T) {
	now := time.Date(2026, 5, 7, 14, 32, 11, 0, time.UTC)
	in := types.TokenResponse{
		AccessToken:         "abc.def.ghi",
		TokenType:           "Bearer",
		ExpiresAt:           now.Add(15 * time.Minute),
		RefreshWindowEndsAt: now.Add(4 * time.Hour),
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out types.TokenResponse
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.AccessToken != in.AccessToken || out.TokenType != in.TokenType {
		t.Fatalf("scalar mismatch: %+v", out)
	}
	if !out.ExpiresAt.Equal(in.ExpiresAt) || !out.RefreshWindowEndsAt.Equal(in.RefreshWindowEndsAt) {
		t.Fatalf("time mismatch: %+v", out)
	}
}

func TestProblemDetailsContentType(t *testing.T) {
	if types.ProblemContentType != "application/problem+json" {
		t.Fatalf("got %q", types.ProblemContentType)
	}
}
