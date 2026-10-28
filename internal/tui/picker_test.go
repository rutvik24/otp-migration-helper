package tui

import (
	"bufio"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/rutvik24/otp-migration-helper/internal/migration"
)

func accts(names ...string) []migration.Account {
	out := make([]migration.Account, len(names))
	for i, n := range names {
		out[i] = migration.Account{Name: n}
	}
	return out
}

func press(m tea.Model, keys ...tea.KeyMsg) picker {
	for _, k := range keys {
		m, _ = m.Update(k)
	}
	return m.(picker)
}

var (
	down  = tea.KeyMsg{Type: tea.KeyDown}
	up    = tea.KeyMsg{Type: tea.KeyUp}
	space = tea.KeyMsg{Type: tea.KeySpace}
	enter = tea.KeyMsg{Type: tea.KeyEnter}
	esc   = tea.KeyMsg{Type: tea.KeyEsc}
	home  = tea.KeyMsg{Type: tea.KeyHome}
	end   = tea.KeyMsg{Type: tea.KeyEnd}
)

func runes(r string) tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(r)} }

func names(a []migration.Account) string {
	var n []string
	for _, x := range a {
		n = append(n, x.Name)
	}
	return strings.Join(n, ",")
}

func TestPicker_ToggleOneAndConfirm(t *testing.T) {
	p := press(newPicker(accts("a", "b", "c")), down, down, space, enter) // row 0 is "All accounts"
	if !p.confirmed || names(p.chosen()) != "b" {
		t.Errorf("confirmed=%v chosen=%s", p.confirmed, names(p.chosen()))
	}
}

func TestPicker_AllRowSelectsEverythingAndTogglesBack(t *testing.T) {
	p := press(newPicker(accts("a", "b", "c")), space) // cursor starts on "All accounts"
	if names(p.chosen()) != "a,b,c" {
		t.Errorf("all row: %s", names(p.chosen()))
	}
	p = press(p, space)
	if len(p.chosen()) != 0 {
		t.Errorf("second press should clear: %s", names(p.chosen()))
	}
	if !strings.Contains(press(newPicker(accts("a", "b")), space).View(), "[x] All accounts") {
		t.Error("the All row should show as checked when everything is selected")
	}
}

func TestPicker_AllRowTracksIndividualChoices(t *testing.T) {
	p := press(newPicker(accts("a", "b")), down, space, down, space)
	if !strings.Contains(p.View(), "[x] All accounts") {
		t.Errorf("choosing every account should check All:\n%s", p.View())
	}
	p = press(p, space)
	if strings.Contains(p.View(), "[x] All accounts") || names(p.chosen()) != "a" {
		t.Errorf("clearing one should uncheck All: %s", names(p.chosen()))
	}
}

func TestPicker_ShortcutKeys(t *testing.T) {
	if p := press(newPicker(accts("a", "b")), runes("a")); names(p.chosen()) != "a,b" {
		t.Errorf("a selects all: %s", names(p.chosen()))
	}
	if p := press(newPicker(accts("a", "b")), runes("a"), runes("n")); len(p.chosen()) != 0 {
		t.Errorf("n selects none: %s", names(p.chosen()))
	}
	if p := press(newPicker(accts("a", "b", "c")), end); p.cursor != 3 {
		t.Errorf("end: cursor %d", p.cursor)
	}
	if p := press(newPicker(accts("a", "b", "c")), end, home); p.cursor != 0 {
		t.Errorf("home: cursor %d", p.cursor)
	}
	if p := press(newPicker(accts("a", "b")), runes("j"), runes("j"), runes("k")); p.cursor != 1 {
		t.Errorf("j/k: cursor %d", p.cursor)
	}
	if p := press(newPicker(accts("a", "b")), up); p.cursor != 0 {
		t.Errorf("up at the top stays: %d", p.cursor)
	}
}

func TestPicker_EnterWithNothingChosenTakesTheHighlightedOne(t *testing.T) {
	if p := press(newPicker(accts("a", "b")), down, down, enter); !p.confirmed || names(p.chosen()) != "b" {
		t.Errorf("chosen %s", names(p.chosen()))
	}
	if p := press(newPicker(accts("a", "b")), enter); names(p.chosen()) != "a,b" {
		t.Errorf("enter on All with nothing chosen means all: %s", names(p.chosen()))
	}
}

func TestPicker_CancelKeys(t *testing.T) {
	for _, k := range []tea.KeyMsg{runes("q"), esc, {Type: tea.KeyCtrlC}} {
		if p := press(newPicker(accts("a")), space, k); !p.cancelled {
			t.Errorf("%v should cancel", k)
		}
	}
}

func TestSelect_Specs(t *testing.T) {
	all := accts("alice", "bob", "carol")
	cases := map[string]string{
		"all":         "alice,bob,carol",
		"ALL":         "alice,bob,carol",
		"2":           "bob",
		"1,3":         "alice,carol",
		"1 3":         "alice,carol",
		"3,1":         "alice,carol", // keeps the vault's order, no duplicates
		"bob":         "bob",
		"ali, 2":      "alice,bob",
		"1-2":         "alice,bob",
		"alice,alice": "alice",
	}
	for spec, want := range cases {
		got, err := Select(all, spec)
		if err != nil || names(got) != want {
			t.Errorf("%q: got %q err %v, want %q", spec, names(got), err, want)
		}
	}
	for _, bad := range []string{"", "  ", "9", "0", "nobody", "2-9", "x-y"} {
		if _, err := Select(all, bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
	if _, err := Select(all, "a"); err == nil || !strings.Contains(err.Error(), "more than one") {
		t.Errorf("an ambiguous name should say so: %v", err)
	}
}

func TestPickFromText(t *testing.T) {
	var out strings.Builder
	got, err := PickFromText(accts("alice", "bob"), bufio.NewReader(strings.NewReader("2\n")), &out)
	if err != nil || names(got) != "bob" {
		t.Fatalf("got=%s err=%v", names(got), err)
	}
	for _, want := range []string{"1) alice", "2) bob", "all"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("prompt missing %q:\n%s", want, out.String())
		}
	}
	// A blank answer means everything; a bad one is asked again once, then reported.
	if got, err := PickFromText(accts("a", "b"), bufio.NewReader(strings.NewReader("\n")), &strings.Builder{}); err != nil || names(got) != "a,b" {
		t.Errorf("blank: %s %v", names(got), err)
	}
	if _, err := PickFromText(accts("a"), bufio.NewReader(strings.NewReader("9\n")), &strings.Builder{}); err == nil {
		t.Error("end of input after a bad answer must be an error")
	}
	if _, err := PickFromText(accts("a"), bufio.NewReader(strings.NewReader("")), &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "--all") {
		t.Errorf("no input at all should suggest --all or --select: %v", err)
	}
}
