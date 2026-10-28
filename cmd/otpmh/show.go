package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/rutvik24/otp-migration-helper/internal/account"
	"github.com/rutvik24/otp-migration-helper/internal/migration"
	"github.com/rutvik24/otp-migration-helper/internal/qrcode"
	"github.com/rutvik24/otp-migration-helper/internal/source"
	"github.com/rutvik24/otp-migration-helper/internal/store"
	"github.com/rutvik24/otp-migration-helper/internal/tui"
)

const secretWarning = "Warning: keep these secret - anyone with a QR code or secret can generate your codes."

func runShow(args []string, stdin io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	fs.SetOutput(out)
	all := fs.Bool("all", false, "show every account without asking")
	useVault := fs.Bool("vault", false, "read accounts from the vault")
	vf := addVaultFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	var accounts []migration.Account
	var vault *store.Store
	if *useVault {
		s, recs, err := vaultAccounts(vf)
		if err != nil {
			return err
		}
		defer func() { _ = s.Close() }()
		vault, accounts = s, accountsOf(recs)
	} else {
		var warnings []string
		var err error
		if accounts, warnings, err = source.Load(fs.Args(), stdin); err != nil {
			return err
		}
		for _, w := range warnings {
			fmt.Fprintln(out, "warning:", w)
		}
	}

	if !*all {
		var err error
		if accounts, err = tui.Pick(accounts); err != nil {
			return err
		}
	}
	if vault != nil {
		if err := vault.Log("show", fmt.Sprintf("accounts=%d", len(accounts))); err != nil {
			return err
		}
	}

	fmt.Fprintln(out, secretWarning)
	for _, a := range accounts {
		url := account.URL(a)
		qr, err := qrcode.Render(url)
		if err != nil {
			return fmt.Errorf("%s: %w", account.Label(a), err)
		}
		fmt.Fprintf(out, "\n== %s ==\nURL:    %s\nSecret: %s\n%s", account.Label(a), url, account.Base32(a.Secret), qr)
	}
	return nil
}
