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
	"errors"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/cli"
)

type statusModel struct {
	g      *cli.Globals
	tok    *cli.StoredToken
	runErr error
	empty  bool
}

func newStatusScreen(g *cli.Globals) statusModel {
	m := statusModel{g: g}
	tok, err := cli.LoadToken(g.TokenPath)
	switch {
	case errors.Is(err, cli.ErrTokenNotFound):
		m.empty = true
	case err != nil:
		m.runErr = err
	default:
		m.tok = &tok
	}
	return m
}

func (m statusModel) Init() tea.Cmd { return nil }

func (m statusModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "esc", "enter", " ", "q":
			return m, gotoScreen(screenHome)
		case "r":
			return newStatusScreen(m.g), nil
		}
	}
	return m, nil
}

func (m statusModel) View() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Status") + "\n\n")
	switch {
	case m.runErr != nil:
		b.WriteString(errorStyle.Render("Error: "+m.runErr.Error()) + "\n\n")
	case m.empty:
		b.WriteString(mutedStyle.Render("no cached token — pick Login from the menu") + "\n\n")
	default:
		now := time.Now().UTC()
		ttl := m.tok.ExpiresAt.Sub(now).Round(time.Second)
		win := m.tok.RefreshWindowEndsAt.Sub(now).Round(time.Second)
		fmt.Fprintf(&b, "%s%s\n", labelStyle.Render("Broker"), m.tok.BrokerURL)
		fmt.Fprintf(&b, "%s%s\n", labelStyle.Render("Token in"), expiryView(ttl))
		fmt.Fprintf(&b, "%s%s\n", labelStyle.Render("Refresh"), expiryView(win)+" remaining")
		b.WriteString("\n")
	}
	b.WriteString(helpStyle.Render("enter back to menu  •  r refresh"))
	return b.String()
}

func expiryView(d time.Duration) string {
	if d <= 0 {
		return errorStyle.Render("expired")
	}
	return d.String()
}
