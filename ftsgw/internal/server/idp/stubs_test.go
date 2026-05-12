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

package idp_test

import (
	"context"
	"errors"
	"testing"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/idp"
)

func TestEntraStubReturnsNotImplemented(t *testing.T) {
	p := idp.EntraProvider{}
	_, err := p.Authenticate(context.Background(), "alice", "p")
	if !errors.Is(err, idp.ErrNotImplemented) {
		t.Fatalf("got %v", err)
	}
}

func TestADFSStubReturnsNotImplemented(t *testing.T) {
	p := idp.ADFSProvider{}
	_, err := p.Authenticate(context.Background(), "alice", "p")
	if !errors.Is(err, idp.ErrNotImplemented) {
		t.Fatalf("got %v", err)
	}
}

func TestCapabilitiesDefaults(t *testing.T) {
	got := idp.ADFSProvider{}.Capabilities()
	if got.SupportsPassword || got.SupportsChallenge {
		t.Fatalf("unexpected: %+v", got)
	}
}
