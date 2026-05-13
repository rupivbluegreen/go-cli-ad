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

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/cli"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/pkg/api/types"
)

type whoamiState int

const (
	whoamiStateLoading whoamiState = iota
	whoamiStateResult
	whoamiStateError
)

type whoamiModel struct {
	g       *cli.Globals
	state   whoamiState
	spinner spinner.Model
	me      *types.MeResponse
	runErr  error
}

type whoamiDoneMsg struct {
	me  *types.MeResponse
	err error
}

func newWhoamiScreen(g *cli.Globals) whoamiModel {
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	return whoamiModel{g: g, state: whoamiStateLoading, spinner: sp}
}

func (m whoamiModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, m.fetch())
}

func (m whoamiModel) fetch() tea.Cmd {
	g := m.g
	return func() tea.Msg {
		if g.BrokerURL == "" {
			return whoamiDoneMsg{err: errors.New("broker URL not configured")}
		}
		c, err := cli.NewClient(cli.ClientConfig{
			BrokerURL:    g.BrokerURL,
			TokenPath:    g.TokenPath,
			CABundlePath: g.CABundlePath,
		})
		if err != nil {
			return whoamiDoneMsg{err: err}
		}
		me, err := c.Me()
		return whoamiDoneMsg{me: me, err: err}
	}
}

func (m whoamiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc", "enter", " ":
			if m.state != whoamiStateLoading {
				return m, gotoScreen(screenHome)
			}
		case "r":
			if m.state != whoamiStateLoading {
				return newWhoamiScreen(m.g), tea.Batch(m.spinner.Tick, newWhoamiScreen(m.g).fetch())
			}
		}
	case whoamiDoneMsg:
		if msg.err != nil {
			m.runErr = msg.err
			m.state = whoamiStateError
		} else {
			m.me = msg.me
			m.state = whoamiStateResult
		}
		return m, nil
	case spinner.TickMsg:
		if m.state == whoamiStateLoading {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			return m, cmd
		}
	}
	return m, nil
}

func (m whoamiModel) View() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Whoami") + "\n\n")
	switch m.state {
	case whoamiStateLoading:
		b.WriteString(m.spinner.View() + " loading identity…")
	case whoamiStateResult:
		fmt.Fprintf(&b, "%s%s\n", labelStyle.Render("UPN"), m.me.UPN)
		fmt.Fprintf(&b, "%s%s\n", labelStyle.Render("Name"), m.me.DisplayName)
		fmt.Fprintf(&b, "%s%d group(s)\n", labelStyle.Render("Groups"), len(m.me.Groups))
		for _, g := range m.me.Groups {
			b.WriteString("  • " + g + "\n")
		}
		b.WriteString("\n" + helpStyle.Render("enter back to menu  •  r refresh"))
	case whoamiStateError:
		b.WriteString(errorStyle.Render("Error: " + m.runErr.Error()))
		b.WriteString("\n\n" + helpStyle.Render("enter back to menu  •  r retry"))
	}
	return b.String()
}
