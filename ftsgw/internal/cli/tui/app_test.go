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

package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/cli"
)

// TestHomeRenderAndNavigate verifies the home screen lists the expected entries
// and that pressing "enter" emits a transitionMsg for the highlighted target.
func TestHomeRenderAndNavigate(t *testing.T) {
	a := newApp(&cli.Globals{TokenPath: "/dev/null"})
	view := a.View()
	for _, want := range []string{"ftsgw-cli", "Login", "Whoami", "Status", "Logout"} {
		if !strings.Contains(view, want) {
			t.Errorf("home view missing %q\n%s", want, view)
		}
	}

	// Press "down" twice to land on "Status" (third entry), then enter.
	out, _ := a.Update(tea.KeyMsg{Type: tea.KeyDown})
	a = out.(appModel)
	out, _ = a.Update(tea.KeyMsg{Type: tea.KeyDown})
	a = out.(appModel)
	_, cmd := a.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("expected a transition cmd on enter")
	}
	msg := cmd()
	tr, ok := msg.(transitionMsg)
	if !ok {
		t.Fatalf("expected transitionMsg, got %T", msg)
	}
	if tr.target != screenStatus {
		t.Errorf("target = %d, want screenStatus (%d)", tr.target, screenStatus)
	}
}

// TestStatusScreenShowsEmptyWhenNoToken renders the status view against a
// token path that doesn't exist; should print the "no cached token" line.
func TestStatusScreenShowsEmptyWhenNoToken(t *testing.T) {
	m := newStatusScreen(&cli.Globals{TokenPath: t.TempDir() + "/no-such-token.json"})
	view := m.View()
	if !strings.Contains(view, "no cached token") {
		t.Errorf("expected empty-token hint, got:\n%s", view)
	}
}

// TestLoginScreenRendersFormFields verifies the login form lays out both
// fields and shows the broker URL when configured.
func TestLoginScreenRendersFormFields(t *testing.T) {
	m := newLoginScreen(&cli.Globals{BrokerURL: "https://broker.test:8443", TokenPath: "/tmp/no.json"})
	view := m.View()
	for _, want := range []string{"Username", "Password", "broker.test"} {
		if !strings.Contains(view, want) {
			t.Errorf("login view missing %q\n%s", want, view)
		}
	}
}
