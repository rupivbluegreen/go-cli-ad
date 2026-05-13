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
			{title: "Login", desc: "Authenticate with the broker (username + password)", target: screenLogin},
			{title: "Whoami", desc: "Show identity and groups from the cached token", target: screenWhoami},
			{title: "Status", desc: "Show token expiry and refresh-window remaining", target: screenStatus},
			{title: "Logout", desc: "Revoke the current token and clear the local cache", target: screenLogout},
		},
	}
}

func (h homeModel) Init() tea.Cmd { return nil }

func (h homeModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m, ok := msg.(tea.KeyMsg); ok {
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
	b.WriteString(titleStyle.Render("ftsgw-cli") + "\n")
	b.WriteString(subtitleStyle.Render("authenticate · inspect tokens · sign out") + "\n\n")
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
