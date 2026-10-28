package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/rutvik24/otp-migration-helper/internal/migration"
	"github.com/rutvik24/otp-migration-helper/internal/qrcode"
)

const qrPNGSize = 640

// runQR shows Google Authenticator "import accounts" QR codes for accounts, so
// another phone or app can scan them. Many apps read this format: Google
// Authenticator, Aegis, 2FAS, Ente Auth, FreeOTP+, Authenticator Pro, and more.
// From the vault, the vault's own credentials are asked for first.
func runQR(args []string, stdin io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("qr", flag.ContinueOnError)
	fs.SetOutput(out)
	all := fs.Bool("all", false, "use every account without asking")
	pick := fs.String("select", "", "choose accounts without the menu: \"all\", numbers (1,3 or 2-4) or names")
	useVault := fs.Bool("vault", false, "take the accounts from the vault")
	perCode := fs.Int("per-qr", migration.DefaultPerCode, fmt.Sprintf("accounts in each QR code (1 to %d)", migration.MaxPerCode))
	pngDir := fs.String("png-dir", "", "also save each QR code as a PNG image in this folder")
	vf := addVaultFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *perCode < 1 || *perCode > migration.MaxPerCode {
		return fmt.Errorf("--per-qr must be between 1 and %d", migration.MaxPerCode)
	}

	accounts, vault, closeVault, err := loadAccounts(fs.Args(), stdin, out, *useVault, vf)
	if err != nil {
		return err
	}
	defer closeVault()
	if accounts, err = chooseAccounts(accounts, *all, *pick); err != nil {
		return err
	}
	links, err := migration.Encode(accounts, *perCode)
	if err != nil {
		return err
	}
	if vault != nil {
		if err := vault.Log("export_qr", fmt.Sprintf("accounts=%d codes=%d", len(accounts), len(links))); err != nil {
			return err
		}
	}
	if *pngDir != "" {
		if err := os.MkdirAll(*pngDir, 0o700); err != nil {
			return err
		}
	}

	sayln(out, secretWarning)
	left := len(accounts)
	for i, link := range links {
		inThis := min(*perCode, left)
		left -= inThis
		art, err := qrcode.Render(link)
		if err != nil {
			return err
		}
		plural := "accounts"
		if inThis == 1 {
			plural = "account"
		}
		if _, err := fmt.Fprintf(out, "\n== QR code %d of %d (%d %s) ==\n%s", i+1, len(links), inThis, plural, art); err != nil {
			return err
		}
		if *pngDir != "" {
			if err := writeQRImage(*pngDir, i+1, len(links), link); err != nil {
				return err
			}
		}
	}
	sayln(out, "\nIn Google Authenticator: open the menu, choose Transfer accounts, then Import accounts, and scan each code above in order.")
	sayln(out, "Aegis, 2FAS, Ente Auth, FreeOTP+ and many other apps read the same codes from their Import options.")
	if *pngDir != "" {
		say(out, "Images saved in %s (they are not encrypted: delete them after importing).\n", *pngDir)
	}
	return nil
}

func writeQRImage(dir string, n, of int, link string) error {
	data, err := qrcode.PNG(link, qrPNGSize)
	if err != nil {
		return err
	}
	name := filepath.Join(dir, fmt.Sprintf("otpmh-import-%d-of-%d.png", n, of))
	f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists; choose an empty folder", name)
		}
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
