package tui

import (
	"errors"
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/rupivbluegreen/go-cli-ad/internal/config"
)

type configInitState int

const (
	cfgInitConfirm configInitState = iota
	cfgInitConfirmOverwrite
	cfgInitDone
	cfgInitError
)

type configInitModel struct {
	path     string
	resolved bool
	exists   bool
	state    configInitState
	err      error
}

func newConfigInitScreen(configPath string) configInitModel {
	m := configInitModel{path: configPath}
	if m.path == "" {
		p, err := config.DefaultPath()
		if err != nil {
			m.err = err
			m.state = cfgInitError
			return m
		}
		m.path = p
	}
	m.resolved = true
	if _, err := os.Stat(m.path); err == nil {
		m.exists = true
	}
	return m
}

func (m configInitModel) Init() tea.Cmd { return nil }

func (m configInitModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			return m, gotoScreen(screenHome)
		case "enter":
			switch m.state {
			case cfgInitConfirm:
				if m.exists {
					m.state = cfgInitConfirmOverwrite
					return m, nil
				}
				return m.write(false)
			case cfgInitConfirmOverwrite:
				return m.write(true)
			case cfgInitDone, cfgInitError:
				return m, gotoScreen(screenHome)
			}
		case "y", "Y":
			if m.state == cfgInitConfirmOverwrite {
				return m.write(true)
			}
		case "n", "N":
			if m.state == cfgInitConfirmOverwrite {
				return m, gotoScreen(screenHome)
			}
		}
	}
	return m, nil
}

func (m configInitModel) write(force bool) (tea.Model, tea.Cmd) {
	if err := config.WriteStarter(m.path, force); err != nil {
		if errors.Is(err, config.ErrAlreadyExists) {
			m.state = cfgInitConfirmOverwrite
			return m, nil
		}
		m.err = err
		m.state = cfgInitError
		return m, nil
	}
	m.state = cfgInitDone
	return m, nil
}

func (m configInitModel) View() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Config: init") + "\n\n")
	switch m.state {
	case cfgInitConfirm:
		fmt.Fprintf(&b, "Will write a starter config to:\n  %s\n\n", m.path)
		if m.exists {
			b.WriteString(errorStyle.Render("⚠ file already exists — you'll be asked to confirm overwrite") + "\n\n")
		}
		b.WriteString(helpStyle.Render("enter write  •  esc cancel"))
	case cfgInitConfirmOverwrite:
		fmt.Fprintf(&b, "Overwrite existing %s?\n\n", m.path)
		b.WriteString(helpStyle.Render("y overwrite  •  n / esc cancel"))
	case cfgInitDone:
		b.WriteString(successStyle.Render("✓ Wrote starter config") + "\n")
		fmt.Fprintf(&b, "  %s\n\n", m.path)
		b.WriteString("Edit it to point at your AD server and Azure tenant.\n")
		b.WriteString("\n" + helpStyle.Render("enter back to menu"))
	case cfgInitError:
		b.WriteString(errorStyle.Render("Error: " + m.err.Error()))
		b.WriteString("\n\n" + helpStyle.Render("enter back to menu"))
	}
	return b.String()
}
