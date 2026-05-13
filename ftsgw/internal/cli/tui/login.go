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
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/cli"
)

const (
	loginFldUsername = iota
	loginFldPassword
	loginFieldCount
)

type loginState int

const (
	loginStateForm loginState = iota
	loginStateRunning
	loginStateResult
	loginStateError
)

type loginModel struct {
	g       *cli.Globals
	inputs  []textinput.Model
	focused int
	state   loginState
	spinner spinner.Model
	runErr  error
	asUser  string
}

type loginDoneMsg struct {
	username string
	err      error
}

func newLoginScreen(g *cli.Globals) loginModel {
	inputs := make([]textinput.Model, loginFieldCount)
	for i := range inputs {
		inputs[i] = textinput.New()
		inputs[i].CharLimit = 256
	}
	inputs[loginFldUsername].Placeholder = "alex"
	inputs[loginFldUsername].SetValue(defaultUsername())
	inputs[loginFldPassword].Placeholder = "••••••••"
	inputs[loginFldPassword].EchoMode = textinput.EchoPassword
	inputs[loginFldPassword].EchoCharacter = '•'

	first := loginFldUsername
	if inputs[loginFldUsername].Value() != "" {
		first = loginFldPassword
	}
	inputs[first].Focus()

	sp := spinner.New()
	sp.Spinner = spinner.Dot
	return loginModel{g: g, inputs: inputs, focused: first, spinner: sp}
}

func (m loginModel) Init() tea.Cmd { return textinput.Blink }

func (m loginModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "esc" {
			if m.state == loginStateRunning {
				return m, nil
			}
			return m, gotoScreen(screenHome)
		}
		switch m.state {
		case loginStateForm:
			return m.updateForm(msg)
		case loginStateResult, loginStateError:
			switch msg.String() {
			case "enter", " ":
				return m, gotoScreen(screenHome)
			case "r":
				return m, gotoScreen(screenLogin)
			}
		}
	case loginDoneMsg:
		if msg.err != nil {
			m.runErr = msg.err
			m.state = loginStateError
		} else {
			m.asUser = msg.username
			m.state = loginStateResult
		}
		return m, nil
	case spinner.TickMsg:
		if m.state == loginStateRunning {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			return m, cmd
		}
	}
	return m, nil
}

func (m loginModel) updateForm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "tab", "down":
		m.focused = (m.focused + 1) % len(m.inputs)
	case "shift+tab", "up":
		m.focused = (m.focused - 1 + len(m.inputs)) % len(m.inputs)
	case "enter":
		if m.focused < len(m.inputs)-1 {
			m.focused++
			break
		}
		if err := m.validate(); err != nil {
			m.runErr = err
			m.state = loginStateError
			return m, nil
		}
		m.state = loginStateRunning
		return m, tea.Batch(m.spinner.Tick, m.submit())
	default:
		var cmd tea.Cmd
		m.inputs[m.focused], cmd = m.inputs[m.focused].Update(msg)
		m.refocus()
		return m, cmd
	}
	m.refocus()
	return m, nil
}

func (m loginModel) refocus() {
	for i := range m.inputs {
		if i == m.focused {
			m.inputs[i].Focus()
		} else {
			m.inputs[i].Blur()
		}
	}
}

func (m loginModel) validate() error {
	if m.g.BrokerURL == "" {
		return errors.New("broker URL not configured (--broker or broker_url in cli.yaml)")
	}
	if strings.TrimSpace(m.inputs[loginFldUsername].Value()) == "" {
		return errors.New("username is required")
	}
	if m.inputs[loginFldPassword].Value() == "" {
		return errors.New("password is required")
	}
	return nil
}

func (m loginModel) submit() tea.Cmd {
	username := strings.TrimSpace(m.inputs[loginFldUsername].Value())
	password := m.inputs[loginFldPassword].Value()
	g := m.g
	return func() tea.Msg {
		c, err := cli.NewClient(cli.ClientConfig{
			BrokerURL:    g.BrokerURL,
			TokenPath:    g.TokenPath,
			CABundlePath: g.CABundlePath,
		})
		if err != nil {
			return loginDoneMsg{err: err}
		}
		if err := c.Login(username, password); err != nil {
			return loginDoneMsg{err: err}
		}
		return loginDoneMsg{username: username}
	}
}

func (m loginModel) View() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Login") + "\n\n")
	if m.g.BrokerURL != "" {
		b.WriteString(mutedStyle.Render("broker: "+m.g.BrokerURL) + "\n\n")
	}
	switch m.state {
	case loginStateForm:
		b.WriteString(labelStyle.Render("Username") + m.inputs[loginFldUsername].View() + "\n")
		b.WriteString(labelStyle.Render("Password") + m.inputs[loginFldPassword].View() + "\n")
		b.WriteString("\n" + helpStyle.Render("tab/↑↓ move  •  enter submit  •  esc back"))
	case loginStateRunning:
		b.WriteString(m.spinner.View() + " contacting broker…")
	case loginStateResult:
		b.WriteString(successStyle.Render("✓ logged in as "+m.asUser))
		b.WriteString("\n\n" + helpStyle.Render("enter back to menu"))
	case loginStateError:
		b.WriteString(errorStyle.Render("Error: " + m.runErr.Error()))
		b.WriteString("\n\n" + helpStyle.Render("enter back to menu  •  r retry"))
	}
	return b.String()
}

func defaultUsername() string {
	if u := os.Getenv("FTSGW_USERNAME"); u != "" {
		return u
	}
	return os.Getenv("USER")
}
