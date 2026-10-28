// Package tui holds the interactive terminal views.
package tui

import (
	"errors"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/rutvik24/otp-migration-helper/internal/account"
	"github.com/rutvik24/otp-migration-helper/internal/migration"
)

var errCancelled = errors.New("cancelled")

type picker struct {
	accounts  []migration.Account
	cursor    int
	selected  map[int]bool
	confirmed bool
	cancelled bool
}

func newPicker(accounts []migration.Account) picker {
	return picker{accounts: accounts, selected: map[int]bool{}}
}

func (p picker) Init() tea.Cmd { return nil }

func (p picker) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return p, nil
	}
	switch key.String() {
	case "up", "k":
		if p.cursor > 0 {
			p.cursor--
		}
	case "down", "j":
		if p.cursor < len(p.accounts)-1 {
			p.cursor++
		}
	case " ":
		p.selected[p.cursor] = !p.selected[p.cursor]
	case "a":
		for i := range p.accounts {
			p.selected[i] = true
		}
	case "enter":
		p.confirmed = true
		return p, tea.Quit
	case "q", "ctrl+c", "esc":
		p.cancelled = true
		return p, tea.Quit
	}
	return p, nil
}

func (p picker) View() string {
	var b strings.Builder
	b.WriteString("Select accounts (space: toggle, a: all, enter: confirm, q: cancel)\n\n")
	for i, a := range p.accounts {
		cursor, mark := " ", " "
		if i == p.cursor {
			cursor = ">"
		}
		if p.selected[i] {
			mark = "x"
		}
		b.WriteString(fmt.Sprintf("%s [%s] %s\n", cursor, mark, account.Label(a)))
	}
	return b.String()
}

func (p picker) chosen() []migration.Account {
	var out []migration.Account
	for i, a := range p.accounts {
		if p.selected[i] {
			out = append(out, a)
		}
	}
	return out
}

// Pick lets the user choose one or more accounts.
func Pick(accounts []migration.Account) ([]migration.Account, error) {
	final, err := tea.NewProgram(newPicker(accounts)).Run()
	if err != nil {
		return nil, err
	}
	p := final.(picker)
	if p.cancelled || !p.confirmed {
		return nil, errCancelled
	}
	if len(p.chosen()) == 0 {
		return nil, errors.New("no accounts selected")
	}
	return p.chosen(), nil
}
