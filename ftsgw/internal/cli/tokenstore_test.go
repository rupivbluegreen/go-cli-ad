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

package cli_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/cli"
)

func TestSaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token.json")
	in := cli.StoredToken{
		AccessToken:         "abc.def.ghi",
		ExpiresAt:           time.Now().Add(15 * time.Minute).UTC(),
		RefreshWindowEndsAt: time.Now().Add(4 * time.Hour).UTC(),
		IssuedAt:            time.Now().UTC(),
		BrokerURL:           "https://broker.example:8443",
	}
	if err := cli.SaveToken(path, in); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := cli.LoadToken(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.AccessToken != in.AccessToken || got.BrokerURL != in.BrokerURL {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("perms = %o", info.Mode().Perm())
		}
	}
}

func TestLoadMissingFileIsErrNotFound(t *testing.T) {
	_, err := cli.LoadToken(filepath.Join(t.TempDir(), "absent.json"))
	if err != cli.ErrTokenNotFound {
		t.Fatalf("got %v", err)
	}
}
