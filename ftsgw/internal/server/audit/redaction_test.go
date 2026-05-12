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

package audit_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/audit"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/store"
)

func TestExtrasMustNotContainSecrets(t *testing.T) {
	dir := t.TempDir()
	st, _ := store.Open(filepath.Join(dir, "f.db"))
	defer func() { _ = st.Close() }()
	path := filepath.Join(dir, "audit.log")
	lg, _ := audit.NewLogger(path, st)
	defer func() { _ = lg.Close() }()
	err := lg.Write(context.Background(), audit.Event{
		TS:        time.Now().UTC(),
		RequestID: "r",
		Event:     audit.EventTokenIssued,
		Outcome:   "success",
		Extras:    map[string]any{"password": "hunter2"},
	})
	if err == nil {
		t.Fatalf("write must reject secret-shaped keys")
	}
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), "hunter2") {
		t.Fatalf("secret leaked to log file")
	}
}
