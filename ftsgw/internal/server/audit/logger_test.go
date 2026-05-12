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
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/audit"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/store"
)

func newLogger(t *testing.T) (*audit.Logger, string, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	st, err := store.Open(filepath.Join(dir, "ftsgw.db"))
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	lg, err := audit.NewLogger(logPath, st)
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	t.Cleanup(func() { _ = lg.Close() })
	return lg, logPath, st
}

func TestLoggerWritesBothSinks(t *testing.T) {
	lg, path, st := newLogger(t)
	ctx := context.Background()
	if err := lg.Write(ctx, audit.Event{
		TS:        time.Now().UTC(),
		RequestID: "req-1",
		ActorUPN:  "alice@example",
		Event:     audit.EventTokenIssued,
		Outcome:   "success",
		Extras:    map[string]any{"jti": "j1", "auth_method": "password"},
	}); err != nil {
		t.Fatalf("write: %v", err)
	}
	// File
	f, _ := os.Open(path)
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		t.Fatalf("no line written")
	}
	var line map[string]any
	if err := json.Unmarshal([]byte(sc.Text()), &line); err != nil {
		t.Fatalf("json: %v", err)
	}
	if line["event"] != string(audit.EventTokenIssued) {
		t.Fatalf("event = %v", line["event"])
	}
	// DB
	var n int
	_ = st.DB.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event_type = ?`, audit.EventTokenIssued).Scan(&n)
	if n != 1 {
		t.Fatalf("DB rows = %d", n)
	}
}
