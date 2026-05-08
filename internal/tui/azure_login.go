package tui

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/rupivbluegreen/go-cli-ad/internal/azure"
	"github.com/rupivbluegreen/go-cli-ad/internal/config"
	"github.com/rupivbluegreen/go-cli-ad/internal/output"
)

type azureLoginState int

const (
	azureStateLoading azureLoginState = iota
	azureStateAwaiting
	azureStateQuerying
	azureStateResult
	azureStateError
)

type azureLoginModel struct {
	cfg     *config.Config
	state   azureLoginState
	spinner spinner.Model
	prompt  azure.DeviceCodePrompt
	result  output.Result
	runErr  error
}

type azurePromptMsg azure.DeviceCodePrompt

type azureLoginDoneMsg struct {
	result output.Result
	err    error
}

func newAzureLoginScreen(configPath string) azureLoginModel {
	cfg, _, _ := loadCfg(configPath)
	if cfg == nil {
		cfg = &config.Config{
			Azure: config.AzureConfig{
				TenantID: config.DefaultAzureTenantID,
				ClientID: config.DefaultAzureClientID,
			},
		}
	}
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	return azureLoginModel{cfg: cfg, state: azureStateLoading, spinner: sp}
}

func (m azureLoginModel) Init() tea.Cmd {
	promptCh := make(chan azure.DeviceCodePrompt, 1)
	doneCh := make(chan azureLoginDoneMsg, 1)
	go runAzureLoginFlow(m.cfg, promptCh, doneCh)
	return tea.Batch(
		m.spinner.Tick,
		func() tea.Msg { return azurePromptMsg(<-promptCh) },
		func() tea.Msg { return <-doneCh },
	)
}

func runAzureLoginFlow(cfg *config.Config, promptCh chan<- azure.DeviceCodePrompt, doneCh chan<- azureLoginDoneMsg) {
	ctx := context.Background()
	cred, cached, err := azure.DeviceCodeLogin(ctx, cfg.Azure.TenantID, cfg.Azure.ClientID, func(p azure.DeviceCodePrompt) {
		promptCh <- p
	})
	if err != nil {
		// Unblock the prompt-receiver in case Azure failed before invoking UserPrompt.
		select {
		case promptCh <- azure.DeviceCodePrompt{}:
		default:
		}
		doneCh <- azureLoginDoneMsg{err: err}
		return
	}
	if path, perr := azure.TokenCachePath(); perr == nil {
		_ = azure.SaveToken(path, cached)
	}
	r, qerr := queryAzure(ctx, cred, false)
	doneCh <- azureLoginDoneMsg{result: r, err: qerr}
}

func (m azureLoginModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc", "enter", " ":
			if m.state == azureStateResult || m.state == azureStateError {
				return m, gotoScreen(screenHome)
			}
		}
	case azurePromptMsg:
		m.prompt = azure.DeviceCodePrompt(msg)
		if m.prompt.UserCode != "" {
			m.state = azureStateAwaiting
		}
		return m, nil
	case azureLoginDoneMsg:
		if msg.err != nil {
			m.runErr = msg.err
			m.state = azureStateError
		} else {
			m.result = msg.result
			m.state = azureStateResult
		}
		return m, nil
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m azureLoginModel) View() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Azure: sign in") + "\n\n")
	switch m.state {
	case azureStateLoading:
		b.WriteString(m.spinner.View() + " contacting Azure…")
	case azureStateAwaiting:
		body := fmt.Sprintf("Open  %s\nEnter %s",
			urlStyle.Render(m.prompt.VerificationURL),
			deviceCodeStyle.Render(m.prompt.UserCode),
		)
		b.WriteString(deviceCodePanel.Render(body))
		b.WriteString("\n\n" + m.spinner.View() + " waiting for sign-in…")
	case azureStateQuerying:
		b.WriteString(m.spinner.View() + " querying Microsoft Graph…")
	case azureStateResult:
		b.WriteString(renderResult(m.result))
		b.WriteString("\n\n" + helpStyle.Render("enter back to menu"))
	case azureStateError:
		b.WriteString(errorStyle.Render("Error: " + m.runErr.Error()))
		b.WriteString("\n\n" + helpStyle.Render("enter back to menu"))
	}
	return b.String()
}

// queryAzure runs Me + MemberOf and shapes the result. Shared by login + roles.
func queryAzure(ctx context.Context, cred azcore.TokenCredential, transitive bool) (output.Result, error) {
	client, err := azure.NewClient(cred)
	if err != nil {
		return output.Result{}, err
	}
	me, err := azure.Me(ctx, client)
	if err != nil {
		return output.Result{}, err
	}
	memberships, err := azure.MemberOf(ctx, client, transitive)
	if err != nil {
		return output.Result{}, err
	}
	r := output.Result{AuthenticatedAs: firstNonEmpty(me.UPN, me.DisplayName)}
	for _, m := range memberships {
		r.Memberships = append(r.Memberships, output.Membership{
			Type: output.MembershipType(m.Type),
			Name: m.DisplayName,
			ID:   m.ID,
		})
	}
	return r, nil
}
