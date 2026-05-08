// Package tui hosts the Bubble Tea TUI that mirrors the CLI's functionality.
// Each screen is its own tea.Model; the root app routes between them via
// transitionMsg.
package tui

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/rupivbluegreen/go-cli-ad/internal/config"
)

// Run launches the TUI. configPath is the explicit --config path or "" for the
// default location.
func Run(configPath string) error {
	p := tea.NewProgram(newApp(configPath), tea.WithAltScreen())
	_, err := p.Run()
	return err
}

type screenID int

const (
	screenHome screenID = iota
	screenOnprem
	screenAzureLogin
	screenAzureRoles
	screenConfigInit
)

// transitionMsg navigates between screens. Sent by child screens.
type transitionMsg struct{ target screenID }

func gotoScreen(s screenID) tea.Cmd {
	return func() tea.Msg { return transitionMsg{target: s} }
}

type appModel struct {
	configPath string
	width      int
	height     int
	current    tea.Model
}

func newApp(configPath string) appModel {
	a := appModel{configPath: configPath}
	a.current = newHomeScreen()
	return a
}

func (a appModel) Init() tea.Cmd { return a.current.Init() }

func (a appModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m := msg.(type) {
	case tea.WindowSizeMsg:
		a.width, a.height = m.Width, m.Height
	case tea.KeyMsg:
		// Global Ctrl+C always quits.
		if m.String() == "ctrl+c" {
			return a, tea.Quit
		}
	case transitionMsg:
		switch m.target {
		case screenHome:
			a.current = newHomeScreen()
		case screenOnprem:
			a.current = newOnpremScreen(a.configPath)
		case screenAzureLogin:
			a.current = newAzureLoginScreen(a.configPath)
		case screenAzureRoles:
			a.current = newAzureRolesScreen()
		case screenConfigInit:
			a.current = newConfigInitScreen(a.configPath)
		}
		return a, a.current.Init()
	}
	var cmd tea.Cmd
	a.current, cmd = a.current.Update(msg)
	return a, cmd
}

func (a appModel) View() string { return a.current.View() }

// loadCfg resolves the config path (explicit or default) and loads it.
// Returns (nil, nil) when the file simply doesn't exist — screens may proceed
// with empty/prompted values in that case.
func loadCfg(explicitPath string) (*config.Config, string, error) {
	path := explicitPath
	if path == "" {
		p, err := config.DefaultPath()
		if err != nil {
			return nil, "", err
		}
		path = p
	}
	cfg, err := config.Load(path)
	if err != nil {
		return nil, path, err
	}
	return cfg, path, nil
}
