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

package obs_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/obs"
)

func TestRedactingHandlerStripsSecretShapedAttrs(t *testing.T) {
	var buf bytes.Buffer
	h := obs.NewRedactingHandler(slog.NewJSONHandler(&buf, nil))
	log := slog.New(h)
	log.Info("hello", "password", "hunter2", "user", "alice", "Authorization", "Bearer abc.def.ghi")
	out := buf.String()
	if strings.Contains(out, "hunter2") || strings.Contains(out, "abc.def.ghi") {
		t.Fatalf("secret leaked: %s", out)
	}
	if !strings.Contains(out, "alice") {
		t.Fatalf("non-secret value lost: %s", out)
	}
}
