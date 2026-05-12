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

package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/auth"
)

func TestPrunerRemovesExpired(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 5, 7, 14, 0, 0, 0, time.UTC)}
	iss, st := newIssuer(t, clk)
	tok, _ := iss.Mint(context.Background(), auth.Subject{UPN: "alice@example"})
	c, _ := iss.Validate(context.Background(), tok.AccessToken)
	_ = st.Revoke(context.Background(), c.JTI, "x", "", c.ExpiresAt)

	clk.now = clk.now.Add(1 * time.Hour) // past exp
	if err := iss.PruneRevocations(context.Background()); err != nil {
		t.Fatalf("prune: %v", err)
	}
	got, _ := st.IsRevoked(context.Background(), c.JTI)
	if got {
		t.Fatalf("expected jti pruned")
	}
}
