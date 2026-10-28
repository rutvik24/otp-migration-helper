package tui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/rutvik24/otp-migration-helper/internal/migration"
	"github.com/rutvik24/otp-migration-helper/internal/otp"
)

var rfcSecret = []byte("12345678901234567890")

func totpAccount() migration.Account {
	return migration.Account{Name: "t", Secret: rfcSecret, Digits: 8, Kind: migration.TOTP}
}

func hotpAccount() migration.Account {
	return migration.Account{Name: "h", Secret: rfcSecret, Digits: 6, Kind: migration.HOTP}
}

func clockAt(sec int64) *time.Time {
	t := time.Unix(sec, 0)
	return &t
}

func newTestLive(now *time.Time, accounts ...migration.Account) live {
	return newLive(accounts, func() time.Time { return *now })
}

func TestLive_TotpShowsCodeAndSeconds(t *testing.T) {
	m := newTestLive(clockAt(59), totpAccount())
	if v := m.View(); !strings.Contains(v, "94287082") || !strings.Contains(v, "1s") {
		t.Errorf("view:\n%s", v)
	}
}

func TestLive_RolloverChangesCode(t *testing.T) {
	now := clockAt(59)
	m := newTestLive(now, totpAccount())
	*now = time.Unix(60, 0)
	next, _ := m.Update(tickMsg{})
	want := otp.TOTP(rfcSecret, *now, 30, 8, otp.SHA1)
	if v := next.View(); !strings.Contains(v, want) || strings.Contains(v, "94287082") {
		t.Errorf("view:\n%s", v)
	}
}

func TestLive_HotpAdvancesOnlyOnN(t *testing.T) {
	now := clockAt(0)
	var m tea.Model = newTestLive(now, hotpAccount())
	m, _ = m.Update(tickMsg{})
	if v := m.View(); !strings.Contains(v, "755224") {
		t.Fatalf("before n:\n%s", v)
	}
	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	if v := m.View(); !strings.Contains(v, "287082") {
		t.Errorf("after n:\n%s", v)
	}
}

func TestLive_QQuits(t *testing.T) {
	m := newTestLive(clockAt(0), totpAccount())
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if cmd == nil {
		t.Fatal("expected quit command")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Error("expected QuitMsg")
	}
}

func TestLive_NarrowWidthDoesNotPanic(t *testing.T) {
	m := newTestLive(clockAt(59), totpAccount(), hotpAccount())
	next, _ := m.Update(tea.WindowSizeMsg{Width: 10, Height: 5})
	if next.View() == "" {
		t.Error("empty view")
	}
}
