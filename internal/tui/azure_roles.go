package tui

import (
	"context"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/rupivbluegreen/go-cli-ad/internal/azure"
	"github.com/rupivbluegreen/go-cli-ad/internal/output"
)

type azureRolesState int

const (
	rolesStateLoading azureRolesState = iota
	rolesStateResult
	rolesStateError
)

type azureRolesModel struct {
	state   azureRolesState
	spinner spinner.Model
	result  output.Result
	runErr  error
}

type azureRolesDoneMsg struct {
	result output.Result
	err    error
}

func newAzureRolesScreen() azureRolesModel {
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	return azureRolesModel{state: rolesStateLoading, spinner: sp}
}

func (m azureRolesModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, fetchAzureRoles)
}

func fetchAzureRoles() tea.Msg {
	path, err := azure.TokenCachePath()
	if err != nil {
		return azureRolesDoneMsg{err: err}
	}
	t, err := azure.LoadToken(path)
	if err != nil {
		return azureRolesDoneMsg{err: err}
	}
	cred := azure.CredentialFromCache(t)
	r, err := queryAzure(context.Background(), cred, false)
	return azureRolesDoneMsg{result: r, err: err}
}

func (m azureRolesModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc", "enter", " ":
			if m.state != rolesStateLoading {
				return m, gotoScreen(screenHome)
			}
		}
	case azureRolesDoneMsg:
		if msg.err != nil {
			m.runErr = msg.err
			m.state = rolesStateError
		} else {
			m.result = msg.result
			m.state = rolesStateResult
		}
		return m, nil
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m azureRolesModel) View() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Azure: roles (cached)") + "\n\n")
	switch m.state {
	case rolesStateLoading:
		b.WriteString(m.spinner.View() + " loading cached token and querying Graph…")
	case rolesStateResult:
		b.WriteString(renderResult(m.result))
		b.WriteString("\n\n" + helpStyle.Render("enter back to menu"))
	case rolesStateError:
		b.WriteString(errorStyle.Render("Error: " + m.runErr.Error()))
		b.WriteString("\n\n" + helpStyle.Render("enter back to menu"))
	}
	return b.String()
}
