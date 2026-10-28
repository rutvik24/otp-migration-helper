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
  otpmh vault init|import|list|log     encrypted local vault (see README)
  otpmh help

Inputs can be mixed in any order: QR image paths, decoded QR text
(otpauth-migration:// links, or otpauth:// URIs for single accounts). With none
given they are read from stdin, one per line.`

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		sayln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, out io.Writer) error {
	if len(args) == 0 {
		sayln(out, usage)
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
	case "vault":
		return runVault(args[1:], stdin, out)
	case "help", "-h", "--help":
		sayln(out, usage)
		return nil
	default:
		return fmt.Errorf("unknown command %q\n\n%s", args[0], usage)
	}
}

// say and sayln print status messages. A failed write to the terminal has
// nowhere better to be reported, so the error is discarded here, once.
// Output that is the point of a command (secrets, lists, exports) returns
// its write errors instead.
func say(w io.Writer, format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }

func sayln(w io.Writer, a ...any) { _, _ = fmt.Fprintln(w, a...) }
