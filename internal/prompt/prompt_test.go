package prompt

import "testing"

func TestSecret_NonTerminalErrors(t *testing.T) {
	if _, err := Secret("x"); err == nil {
		t.Error("expected error when stdin is not a terminal")
	}
}
