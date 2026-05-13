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

// Package tui hosts the ftsgw-cli Bubble Tea TUI. Each screen is its own
// tea.Model; the root appModel routes between them via transitionMsg.
package tui

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/cli"
)

// Run launches the TUI against the resolved CLI globals (broker URL, token
// path, CA bundle path). Wired from package main via cli.SetTUIRunner.
func Run(g *cli.Globals) error {
	p := tea.NewProgram(newApp(g), tea.WithAltScreen())
	_, err := p.Run()
	return err
}

type screenID int

const (
	screenHome screenID = iota
	screenLogin
	screenWhoami
	screenStatus
	screenLogout
)

// transitionMsg navigates between screens. Sent by child screens.
type transitionMsg struct{ target screenID }

func gotoScreen(s screenID) tea.Cmd {
	return func() tea.Msg { return transitionMsg{target: s} }
}

type appModel struct {
	g       *cli.Globals
	current tea.Model
}

func newApp(g *cli.Globals) appModel {
	a := appModel{g: g}
	a.current = newHomeScreen()
	return a
}

func (a appModel) Init() tea.Cmd { return a.current.Init() }

func (a appModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m := msg.(type) {
	case tea.KeyMsg:
		if m.String() == "ctrl+c" {
			return a, tea.Quit
		}
	case transitionMsg:
		switch m.target {
		case screenHome:
			a.current = newHomeScreen()
		case screenLogin:
			a.current = newLoginScreen(a.g)
		case screenWhoami:
			a.current = newWhoamiScreen(a.g)
		case screenStatus:
			a.current = newStatusScreen(a.g)
		case screenLogout:
			a.current = newLogoutScreen(a.g)
		}
		return a, a.current.Init()
	}
	var cmd tea.Cmd
	a.current, cmd = a.current.Update(msg)
	return a, cmd
}

func (a appModel) View() string { return a.current.View() }
