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

func FuzzValidate(f *testing.F) {
	clk := &fakeClock{now: time.Date(2026, 5, 7, 14, 0, 0, 0, time.UTC)}
	iss, _ := newIssuer(f, clk)
	tok, _ := iss.Mint(context.Background(), auth.Subject{UPN: "alice"})
	f.Add("not.a.jwt")
	f.Add(tok.AccessToken)
	f.Fuzz(func(t *testing.T, raw string) {
		_, _ = iss.Validate(context.Background(), raw) // must not panic
	})
}
