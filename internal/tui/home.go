package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

type homeItem struct {
	title  string
	desc   string
	target screenID
}

type homeModel struct {
	items  []homeItem
	cursor int
}

func newHomeScreen() homeModel {
	return homeModel{
		items: []homeItem{
			{title: "On-prem AD lookup", desc: "Bind to LDAP and list group memberships", target: screenOnprem},
			{title: "Azure: sign in", desc: "Run device-code flow; lists roles + groups when done", target: screenAzureLogin},
			{title: "Azure: roles (cached)", desc: "Re-list using the cached token (no re-auth)", target: screenAzureRoles},
			{title: "Config: init", desc: "Write a starter config file", target: screenConfigInit},
		},
	}
}

func (h homeModel) Init() tea.Cmd { return nil }

func (h homeModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m := msg.(type) {
	case tea.KeyMsg:
		switch m.String() {
		case "q", "esc":
			return h, tea.Quit
		case "up", "k":
			if h.cursor > 0 {
				h.cursor--
			}
		case "down", "j":
			if h.cursor < len(h.items)-1 {
				h.cursor++
			}
		case "enter", " ":
			return h, gotoScreen(h.items[h.cursor].target)
		}
	}
	return h, nil
}

func (h homeModel) View() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("go-cli-ad") + "\n")
	b.WriteString(subtitleStyle.Render("authenticate · list groups & roles") + "\n\n")
	for i, item := range h.items {
		cursor := "  "
		title := unselectedStyle.Render(item.title)
		if i == h.cursor {
			cursor = "▸ "
			title = selectedStyle.Render(item.title)
		}
		fmt.Fprintf(&b, "%s%s\n", cursor, title)
		b.WriteString("    " + helpStyle.Render(item.desc) + "\n\n")
	}
	b.WriteString(helpStyle.Render("↑/↓ navigate  •  enter select  •  q quit"))
	return b.String()
}
