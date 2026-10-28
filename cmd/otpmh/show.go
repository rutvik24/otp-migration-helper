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

// chooseAccounts applies --all or --select, and otherwise opens the menu.
func chooseAccounts(accounts []migration.Account, all bool, spec string) ([]migration.Account, error) {
	switch {
	case all:
		return accounts, nil
	case spec != "":
		return tui.Select(accounts, spec)
	}
	return tui.Pick(accounts)
}

// loadAccounts reads accounts from the vault (asking for its credentials) or
// from links, images and text. When it opened the vault it returns it so the
// caller can log; closeVault is always safe to call.
func loadAccounts(inputs []string, stdin io.Reader, out io.Writer, useVault bool, vf *vaultFlags) ([]migration.Account, *store.Store, func(), error) {
	if useVault {
		s, recs, err := vaultAccounts(vf)
		if err != nil {
			return nil, nil, func() {}, err
		}
		return accountsOf(recs), s, func() { _ = s.Close() }, nil
	}
	accounts, warnings, err := source.Load(inputs, stdin)
	if err != nil {
		return nil, nil, func() {}, err
	}
	for _, w := range warnings {
		sayln(out, "warning:", w)
	}
	return accounts, nil, func() {}, nil
}

func runShow(args []string, stdin io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	fs.SetOutput(out)
	all := fs.Bool("all", false, "show every account without asking")
	pick := fs.String("select", "", "choose accounts without the menu: \"all\", numbers (1,3 or 2-4) or names")
	useVault := fs.Bool("vault", false, "read accounts from the vault")
	vf := addVaultFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	accounts, vault, closeVault, err := loadAccounts(fs.Args(), stdin, out, *useVault, vf)
	if err != nil {
		return err
	}
	defer closeVault()

	if accounts, err = chooseAccounts(accounts, *all, *pick); err != nil {
		return err
	}
	if vault != nil {
		if err := vault.Log("show", fmt.Sprintf("accounts=%d", len(accounts))); err != nil {
			return err
		}
	}

	sayln(out, secretWarning)
	for _, a := range accounts {
		url := account.URL(a)
		qr, err := qrcode.Render(url)
		if err != nil {
			return fmt.Errorf("%s: %w", account.Label(a), err)
		}
		if _, err := fmt.Fprintf(out, "\n== %s ==\nURL:    %s\nSecret: %s\n%s", account.Label(a), url, account.Base32(a.Secret), qr); err != nil {
			return err
		}
	}
	return nil
}
