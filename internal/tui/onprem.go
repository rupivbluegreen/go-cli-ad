package tui

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/rupivbluegreen/go-cli-ad/internal/onprem"
	"github.com/rupivbluegreen/go-cli-ad/internal/output"
)

const (
	fldServer = iota
	fldBaseDN
	fldUsername
	fldPassword
	onpremFieldCount
)

type onpremState int

const (
	onpremStateForm onpremState = iota
	onpremStateRunning
	onpremStateResult
	onpremStateError
)

type onpremModel struct {
	configPath string
	bindFmt    string
	inputs     []textinput.Model
	focused    int
	state      onpremState
	spinner    spinner.Model
	result     output.Result
	runErr     error
	cfgWarning string
}

type onpremDoneMsg struct {
	result output.Result
	err    error
}

func newOnpremScreen(configPath string) onpremModel {
	cfg, _, cfgErr := loadCfg(configPath)

	inputs := make([]textinput.Model, onpremFieldCount)
	for i := range inputs {
		inputs[i] = textinput.New()
		inputs[i].CharLimit = 256
	}
	inputs[fldServer].Placeholder = "ldaps://dc.corp.example.com"
	inputs[fldBaseDN].Placeholder = "DC=corp,DC=example,DC=com"
	inputs[fldUsername].Placeholder = "alex"
	inputs[fldPassword].Placeholder = "••••••••"
	inputs[fldPassword].EchoMode = textinput.EchoPassword
	inputs[fldPassword].EchoCharacter = '•'

	bindFmt := "upn"
	if cfg != nil {
		inputs[fldServer].SetValue(cfg.Onprem.Server)
		inputs[fldBaseDN].SetValue(cfg.Onprem.BaseDN)
		inputs[fldUsername].SetValue(firstNonEmpty(cfg.Onprem.Username, os.Getenv("USER")))
		if cfg.Onprem.BindFormat != "" {
			bindFmt = cfg.Onprem.BindFormat
		}
	} else {
		inputs[fldUsername].SetValue(os.Getenv("USER"))
	}
	inputs[fldServer].Focus()

	sp := spinner.New()
	sp.Spinner = spinner.Dot

	m := onpremModel{
		configPath: configPath,
		bindFmt:    bindFmt,
		inputs:     inputs,
		spinner:    sp,
	}
	if cfgErr != nil && !errors.Is(cfgErr, os.ErrNotExist) {
		// Soft warning — user can still type values manually.
		m.cfgWarning = cfgErr.Error()
	}
	return m
}

func (m onpremModel) Init() tea.Cmd { return textinput.Blink }

func (m onpremModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			if m.state == onpremStateRunning {
				return m, nil
			}
			return m, gotoScreen(screenHome)
		}
		switch m.state {
		case onpremStateForm:
			return m.updateForm(msg)
		case onpremStateResult, onpremStateError:
			switch msg.String() {
			case "enter", " ":
				return m, gotoScreen(screenHome)
			case "r":
				return m, gotoScreen(screenOnprem)
			}
		}
	case onpremDoneMsg:
		if msg.err != nil {
			m.runErr = msg.err
			m.state = onpremStateError
		} else {
			m.result = msg.result
			m.state = onpremStateResult
		}
		return m, nil
	case spinner.TickMsg:
		if m.state == onpremStateRunning {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			return m, cmd
		}
	}
	return m, nil
}

func (m onpremModel) updateForm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
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
		// On the last field, submit.
		if err := m.validate(); err != nil {
			m.runErr = err
			m.state = onpremStateError
			return m, nil
		}
		m.state = onpremStateRunning
		return m, tea.Batch(m.spinner.Tick, m.submit())
	default:
		var cmd tea.Cmd
		m.inputs[m.focused], cmd = m.inputs[m.focused].Update(msg)
		// Refocus
		for i := range m.inputs {
			if i == m.focused {
				m.inputs[i].Focus()
			} else {
				m.inputs[i].Blur()
			}
		}
		return m, cmd
	}
	for i := range m.inputs {
		if i == m.focused {
			m.inputs[i].Focus()
		} else {
			m.inputs[i].Blur()
		}
	}
	return m, nil
}

func (m onpremModel) validate() error {
	if strings.TrimSpace(m.inputs[fldServer].Value()) == "" {
		return errors.New("server is required (e.g. ldaps://dc.corp.example.com)")
	}
	if strings.TrimSpace(m.inputs[fldBaseDN].Value()) == "" {
		return errors.New("base DN is required")
	}
	if strings.TrimSpace(m.inputs[fldUsername].Value()) == "" {
		return errors.New("username is required")
	}
	if m.inputs[fldPassword].Value() == "" {
		return errors.New("password is required")
	}
	return nil
}

func (m onpremModel) submit() tea.Cmd {
	server := m.inputs[fldServer].Value()
	baseDN := m.inputs[fldBaseDN].Value()
	username := m.inputs[fldUsername].Value()
	password := m.inputs[fldPassword].Value()
	bindFmt := m.bindFmt
	return func() tea.Msg {
		r, err := runOnprem(server, baseDN, username, password, bindFmt)
		return onpremDoneMsg{result: r, err: err}
	}
}

func runOnprem(server, baseDN, username, password, bindFmt string) (output.Result, error) {
	client, err := onprem.Dial(onprem.DialOptions{Server: server, BaseDN: baseDN})
	if err != nil {
		return output.Result{}, err
	}
	defer client.Close()
	if err := client.Bind(username, password, bindFmt, baseDN); err != nil {
		return output.Result{}, err
	}
	sam := strings.TrimSuffix(strings.Split(username, "@")[0], `\`)
	if i := strings.Index(username, `\`); i >= 0 {
		sam = username[i+1:]
	}
	userDN, err := client.LookupUser(sam)
	if err != nil {
		return output.Result{}, err
	}
	groups, err := client.Groups(userDN, true)
	if err != nil {
		return output.Result{}, err
	}
	r := output.Result{AuthenticatedAs: userDN}
	for _, g := range groups {
		r.Memberships = append(r.Memberships, output.Membership{
			Type: output.TypeGroup,
			Name: g.CN,
			ID:   g.DN,
		})
	}
	return r, nil
}

func (m onpremModel) View() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("On-prem AD lookup") + "\n\n")
	if m.cfgWarning != "" {
		b.WriteString(errorStyle.Render("config warning: "+m.cfgWarning) + "\n\n")
	}
	switch m.state {
	case onpremStateForm:
		b.WriteString(renderField("Server", m.inputs[fldServer]))
		b.WriteString(renderField("Base DN", m.inputs[fldBaseDN]))
		b.WriteString(renderField("Username", m.inputs[fldUsername]))
		b.WriteString(renderField("Password", m.inputs[fldPassword]))
		b.WriteString("\n" + helpStyle.Render(fmt.Sprintf("bind format: %s   •   tab/↑↓ move   •   enter submit   •   esc back", m.bindFmt)))
	case onpremStateRunning:
		b.WriteString(m.spinner.View() + " binding and querying directory…")
	case onpremStateResult:
		b.WriteString(renderResult(m.result))
		b.WriteString("\n\n" + helpStyle.Render("enter back to menu  •  r run again"))
	case onpremStateError:
		b.WriteString(errorStyle.Render("Error: "+m.runErr.Error()))
		b.WriteString("\n\n" + helpStyle.Render("enter back to menu  •  r retry"))
	}
	return b.String()
}

func renderField(label string, ti textinput.Model) string {
	return labelStyle.Render(label) + ti.View() + "\n"
}

func renderResult(r output.Result) string {
	var buf bytes.Buffer
	if err := output.RenderText(&buf, r); err != nil {
		return errorStyle.Render("render error: " + err.Error())
	}
	// Replace plain tags from the renderer with styled ones for a bit of polish.
	s := buf.String()
	s = strings.ReplaceAll(s, "[G]", tagGroup)
	s = strings.ReplaceAll(s, "[R]", tagRole)
	s = strings.ReplaceAll(s, "[ ]", tagOther)
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
