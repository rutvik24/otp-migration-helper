// Command otpmh decodes Google Authenticator exports and shows them for migration.
package main

import (
	"fmt"
	"io"
	"os"
)

const usage = `otpmh - migrate Google Authenticator accounts

Usage:
  otpmh show [--all] [link|image ...]   show URL, secret and QR for accounts
  otpmh live [--all] [link|image ...]   live TOTP/HOTP codes with timers (q quits)
  otpmh scan [--method capture|shortcut] [--all]   macOS: scan QR codes from the screen
  otpmh install-shortcuts               macOS: add scanning shortcuts to the Shortcuts app
  otpmh help

Inputs are otpauth-migration:// links or QR image paths; with none given,
links are read from stdin, one per line.`

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, out io.Writer) error {
	if len(args) == 0 {
		fmt.Fprintln(out, usage)
		return nil
	}
	switch args[0] {
	case "show":
		return runShow(args[1:], stdin, out)
	case "live":
		return runLive(args[1:], stdin, out)
	case "scan":
		return runScan(args[1:], stdin, out)
	case "install-shortcuts":
		return runInstallShortcuts(out)
	case "help", "-h", "--help":
		fmt.Fprintln(out, usage)
		return nil
	default:
		return fmt.Errorf("unknown command %q\n\n%s", args[0], usage)
	}
}
