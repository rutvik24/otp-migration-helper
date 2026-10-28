package main

import (
	"errors"
	"flag"
	"fmt"
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
	useVault := fs.Bool("vault", false, "read accounts from the vault and save HOTP counters")
	vf := addVaultFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *useVault {
		return liveFromVault(vf, *all)
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
	return tui.Live(accounts, nil)
}

func liveFromVault(vf *vaultFlags, all bool) error {
	s, recs, err := vaultAccounts(vf)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()

	accounts := accountsOf(recs)
	if !all {
		if accounts, err = tui.Pick(accounts); err != nil {
			return err
		}
		recs = matching(recs, accounts)
	}
	if err := s.Log("live", fmt.Sprintf("accounts=%d", len(accounts))); err != nil {
		return err
	}
	return tui.Live(accounts, counterSaver(s, recs))
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
