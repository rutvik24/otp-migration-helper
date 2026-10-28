package main

import (
	"errors"
	"flag"
	"io"
	"os"

	"github.com/rutvik24/otp-migration-helper/internal/source"
	"github.com/rutvik24/otp-migration-helper/internal/tui"
)

func runLive(args []string, stdin io.Reader, out io.Writer) error {
	if !isTerminal(out) {
		return errors.New("live view needs an interactive terminal")
	}
	fs := flag.NewFlagSet("live", flag.ContinueOnError)
	fs.SetOutput(out)
	all := fs.Bool("all", false, "show every account without asking")
	if err := fs.Parse(args); err != nil {
		return err
	}

	accounts, _, err := source.Load(fs.Args(), stdin)
	if err != nil {
		return err
	}
	if !*all {
		if accounts, err = tui.Pick(accounts); err != nil {
			return err
		}
	}
	return tui.Live(accounts)
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
