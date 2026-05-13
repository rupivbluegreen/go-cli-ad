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
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/cli"
)

type logoutState int

const (
	logoutStateConfirm logoutState = iota
	logoutStateRunning
	logoutStateResult
	logoutStateError
)

type logoutModel struct {
	g       *cli.Globals
	state   logoutState
	spinner spinner.Model
	runErr  error
}

type logoutDoneMsg struct{ err error }

func newLogoutScreen(g *cli.Globals) logoutModel {
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	return logoutModel{g: g, state: logoutStateConfirm, spinner: sp}
}

func (m logoutModel) Init() tea.Cmd { return nil }

func (m logoutModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch m.state {
		case logoutStateConfirm:
			switch msg.String() {
			case "esc", "n", "N":
				return m, gotoScreen(screenHome)
			case "y", "Y", "enter":
				m.state = logoutStateRunning
				return m, tea.Batch(m.spinner.Tick, m.submit())
			}
		case logoutStateResult, logoutStateError:
			switch msg.String() {
			case "esc", "enter", " ":
				return m, gotoScreen(screenHome)
			}
		}
	case logoutDoneMsg:
		if msg.err != nil {
			m.runErr = msg.err
			m.state = logoutStateError
		} else {
			m.state = logoutStateResult
		}
		return m, nil
	case spinner.TickMsg:
		if m.state == logoutStateRunning {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			return m, cmd
		}
	}
	return m, nil
}

func (m logoutModel) submit() tea.Cmd {
	g := m.g
	return func() tea.Msg {
		if g.BrokerURL == "" {
			return logoutDoneMsg{err: errors.New("broker URL not configured")}
		}
		c, err := cli.NewClient(cli.ClientConfig{
			BrokerURL:    g.BrokerURL,
			TokenPath:    g.TokenPath,
			CABundlePath: g.CABundlePath,
		})
		if err != nil {
			return logoutDoneMsg{err: err}
		}
		return logoutDoneMsg{err: c.Logout()}
	}
}

func (m logoutModel) View() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Logout") + "\n\n")
	switch m.state {
	case logoutStateConfirm:
		b.WriteString("Revoke the current token and clear the local cache?\n\n")
		b.WriteString(helpStyle.Render("y confirm  •  n / esc cancel"))
	case logoutStateRunning:
		b.WriteString(m.spinner.View() + " revoking token…")
	case logoutStateResult:
		b.WriteString(successStyle.Render("✓ logged out") + "\n\n")
		b.WriteString(helpStyle.Render("enter back to menu"))
	case logoutStateError:
		b.WriteString(errorStyle.Render("Error: " + m.runErr.Error()))
		b.WriteString("\n\n" + helpStyle.Render("enter back to menu"))
	}
	return b.String()
}
