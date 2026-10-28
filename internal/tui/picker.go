// Package tui holds the interactive terminal views.
package tui

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/rutvik24/otp-migration-helper/internal/account"
	"github.com/rutvik24/otp-migration-helper/internal/migration"
)

var errCancelled = errors.New("cancelled")

// say prints a prompt or message; a failed write to the terminal has nowhere
// better to be reported.
func say(w io.Writer, format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }

// picker is a checklist. Row 0 is "All accounts"; account i is row i+1.
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

func (p picker) allSelected() bool {
	return len(p.accounts) > 0 && countTrue(p.selected) == len(p.accounts)
}

func countTrue(m map[int]bool) int {
	n := 0
	for _, v := range m {
		if v {
			n++
		}
	}
	return n
}

func (p *picker) setAll(on bool) {
	for i := range p.accounts {
		p.selected[i] = on
	}
}

func (p picker) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return p, nil
	}
	last := len(p.accounts) // rows are 0..len(accounts)
	switch key.String() {
	case "up", "k":
		if p.cursor > 0 {
			p.cursor--
		}
	case "down", "j":
		if p.cursor < last {
			p.cursor++
		}
	case "home", "g":
		p.cursor = 0
	case "end", "G":
		p.cursor = last
	case " ", "x":
		if p.cursor == 0 {
			p.setAll(!p.allSelected())
		} else {
			p.selected[p.cursor-1] = !p.selected[p.cursor-1]
		}
	case "a":
		p.setAll(true)
	case "n":
		p.setAll(false)
	case "enter":
		// Nothing ticked: take the highlighted row, so Enter alone is enough.
		if countTrue(p.selected) == 0 {
			if p.cursor == 0 {
				p.setAll(true)
			} else {
				p.selected[p.cursor-1] = true
			}
		}
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
	b.WriteString("Select accounts\n")
	b.WriteString("  up/down move, space select, a all, n none, enter confirm, q cancel\n\n")
	row := func(i int, checked bool, label string) {
		cursor, mark := " ", " "
		if i == p.cursor {
			cursor = ">"
		}
		if checked {
			mark = "x"
		}
		b.WriteString(fmt.Sprintf("%s [%s] %s\n", cursor, mark, label))
	}
	row(0, p.allSelected(), "All accounts")
	for i, a := range p.accounts {
		row(i+1, p.selected[i], account.Label(a))
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

// Pick lets the user choose one or more accounts. If the full-screen menu
// cannot start (an IDE console, a terminal without a keyboard device), it
// falls back to asking for the choice as typed text.
func Pick(accounts []migration.Account) ([]migration.Account, error) {
	final, err := tea.NewProgram(newPicker(accounts)).Run()
	if err != nil {
		say(os.Stderr, "The interactive menu could not start (%v). Choose by typing instead.\n", err)
		return PickFromText(accounts, bufio.NewReader(os.Stdin), os.Stderr)
	}
	p := final.(picker)
	if p.cancelled || !p.confirmed {
		return nil, errCancelled
	}
	return p.chosen(), nil
}

const noChoiceHint = "pass --all, or --select with numbers or names (for example --select 1,3)"

// PickFromText lists the accounts and reads the choice as a line of text:
// numbers, parts of names, or "all". A blank answer means all.
func PickFromText(accounts []migration.Account, in *bufio.Reader, out io.Writer) ([]migration.Account, error) {
	say(out, "Accounts:\n")
	for i, a := range accounts {
		say(out, "  %d) %s\n", i+1, account.Label(a))
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		say(out, "Choose accounts: numbers like 1,3 or 1-2, part of a name, or \"all\" [all]: ")
		line, err := in.ReadString('\n')
		if strings.TrimSpace(line) == "" && err != nil {
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, fmt.Errorf("no choice could be read: %s", noChoiceHint)
		}
		if strings.TrimSpace(line) == "" {
			return accounts, nil
		}
		chosen, selErr := Select(accounts, line)
		if selErr == nil {
			return chosen, nil
		}
		lastErr = selErr
		say(out, "%v\n", selErr)
	}
	return nil, lastErr
}

var numberRange = regexp.MustCompile(`^(\d+)-(\d+)$`)

// Select picks accounts without a menu. spec is "all", or a list (separated by
// commas or spaces) of 1-based numbers, ranges like 2-4, and names; a name may
// be part of the label if it matches only one account.
func Select(accounts []migration.Account, spec string) ([]migration.Account, error) {
	tokens := strings.FieldsFunc(spec, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' })
	if len(tokens) == 0 {
		return nil, errors.New("choose at least one account")
	}
	picked := map[int]bool{}
	for _, tok := range tokens {
		switch {
		case strings.EqualFold(tok, "all"):
			return accounts, nil
		case numberRange.MatchString(tok):
			m := numberRange.FindStringSubmatch(tok)
			from, _ := strconv.Atoi(m[1])
			to, _ := strconv.Atoi(m[2])
			if from < 1 || to > len(accounts) || from > to {
				return nil, fmt.Errorf("%q is not a valid range: there are %d accounts", tok, len(accounts))
			}
			for i := from; i <= to; i++ {
				picked[i-1] = true
			}
		default:
			if n, err := strconv.Atoi(tok); err == nil {
				if n < 1 || n > len(accounts) {
					return nil, fmt.Errorf("%d is not an account number: there are %d accounts", n, len(accounts))
				}
				picked[n-1] = true
				continue
			}
			i, err := matchName(accounts, tok)
			if err != nil {
				return nil, err
			}
			picked[i] = true
		}
	}
	idx := make([]int, 0, len(picked))
	for i := range picked {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	out := make([]migration.Account, len(idx))
	for k, i := range idx {
		out[k] = accounts[i]
	}
	return out, nil
}

// matchName finds the one account a name refers to: an exact match on the
// label, name or issuer wins; otherwise a part of the label that fits only one.
func matchName(accounts []migration.Account, name string) (int, error) {
	lower := strings.ToLower(name)
	var partial []int
	for i, a := range accounts {
		if strings.EqualFold(account.Label(a), name) || strings.EqualFold(a.Name, name) || strings.EqualFold(a.Issuer, name) {
			return i, nil
		}
		if strings.Contains(strings.ToLower(account.Label(a)), lower) {
			partial = append(partial, i)
		}
	}
	switch len(partial) {
	case 1:
		return partial[0], nil
	case 0:
		return 0, fmt.Errorf("no account matches %q", name)
	}
	return 0, fmt.Errorf("%q matches more than one account; use its number or more of its name", name)
}
