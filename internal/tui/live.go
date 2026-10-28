package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/rutvik24/otp-migration-helper/internal/account"
	"github.com/rutvik24/otp-migration-helper/internal/migration"
	"github.com/rutvik24/otp-migration-helper/internal/otp"
)

const (
	period         = 30
	maxBarWidth    = 30
	warnSeconds    = 5
	hotpAdvanceKey = "n"
)

var (
	okStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	warnStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
)

type tickMsg struct{}

type live struct {
	accounts []migration.Account
	counters []uint64
	cursor   int
	width    int
	clock    func() time.Time
	now      time.Time
}

func newLive(accounts []migration.Account, clock func() time.Time) live {
	counters := make([]uint64, len(accounts))
	for i, a := range accounts {
		counters[i] = a.Counter
	}
	return live{accounts: accounts, counters: counters, width: 80, clock: clock, now: clock()}
}

func tick() tea.Cmd {
	return tea.Tick(time.Second, func(time.Time) tea.Msg { return tickMsg{} })
}

func (m live) Init() tea.Cmd { return tick() }

func (m live) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tickMsg:
		m.now = m.clock()
		return m, tick()
	case tea.WindowSizeMsg:
		m.width = msg.Width
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.accounts)-1 {
				m.cursor++
			}
		case hotpAdvanceKey:
			if m.accounts[m.cursor].Kind == migration.HOTP {
				m.counters[m.cursor]++
			}
		}
	}
	return m, nil
}

func (m live) View() string {
	var b strings.Builder
	b.WriteString("Live codes (q: quit, up/down: select, n: next HOTP code)\n\n")
	for i, a := range m.accounts {
		marker := " "
		if i == m.cursor {
			marker = ">"
		}
		b.WriteString(fmt.Sprintf("%s %s\n", marker, account.Label(a)))
		if a.Kind == migration.HOTP {
			b.WriteString(fmt.Sprintf("    %s  counter %d\n\n", otp.HOTP(a.Secret, m.counters[i], a.Digits, a.Algorithm), m.counters[i]))
			continue
		}
		left := otp.SecondsLeft(m.now, period)
		b.WriteString(fmt.Sprintf("    %s  %2ds %s\n\n", otp.TOTP(a.Secret, m.now, period, a.Digits, a.Algorithm), left, m.bar(left)))
	}
	return b.String()
}

// bar draws the remaining time; it shrinks to fit narrow terminals.
func (m live) bar(left int) string {
	width := min(maxBarWidth, m.width-20)
	if width < 1 {
		return ""
	}
	filled := width * left / period
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	if left <= warnSeconds {
		return warnStyle.Render(bar)
	}
	return okStyle.Render(bar)
}

// Live shows rolling codes full screen until the user presses q.
func Live(accounts []migration.Account) error {
	_, err := tea.NewProgram(newLive(accounts, time.Now), tea.WithAltScreen()).Run()
	return err
}
