// Package prompt reads secrets from the terminal without echoing them.
package prompt

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/term"
)

// Secret asks for a secret on the terminal. It is a variable so tests can
// replace it.
var Secret = func(label string) (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("a terminal is required to enter secrets")
	}
	if _, err := fmt.Fprintf(os.Stderr, "%s: ", label); err != nil {
		return "", err
	}
	secret, err := term.ReadPassword(fd)
	if _, werr := fmt.Fprintln(os.Stderr); err == nil {
		err = werr
	}
	return string(secret), err
}
