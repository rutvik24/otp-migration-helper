package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/rutvik24/otp-migration-helper/internal/migration"
)

func TestPicker_ToggleAndConfirm(t *testing.T) {
	var m tea.Model = newPicker([]migration.Account{{Name: "a"}, {Name: "b"}})
	for _, k := range []tea.KeyMsg{{Type: tea.KeyDown}, {Type: tea.KeySpace}, {Type: tea.KeyEnter}} {
		m, _ = m.Update(k)
	}
	p := m.(picker)
	got := p.chosen()
	if !p.confirmed || len(got) != 1 || got[0].Name != "b" {
		t.Errorf("confirmed=%v chosen=%v", p.confirmed, got)
	}
}
