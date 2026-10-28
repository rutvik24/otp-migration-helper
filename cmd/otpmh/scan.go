package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/rutvik24/otp-migration-helper/internal/macos"
	"github.com/rutvik24/otp-migration-helper/internal/qrcode"
	"github.com/rutvik24/otp-migration-helper/internal/source"
)

var errMacOnly = errors.New("this command only works on macOS; pass a QR image path to `otpmh show` instead")

// supported is replaced in tests.
var supported = macos.Supported

func runScan(args []string, stdin io.Reader, out io.Writer) error {
	if !supported() {
		return errMacOnly
	}
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(out)
	method := fs.String("method", "capture", "capture (drag a box on screen) or shortcut (Shortcuts app)")
	all := fs.Bool("all", false, "show every account without asking")
	if err := fs.Parse(args); err != nil {
		return err
	}

	scan := macos.CaptureRegion
	switch *method {
	case "capture":
	case "shortcut":
		scan = macos.RunScanShortcut
	default:
		return fmt.Errorf("unknown method %q (use capture or shortcut)", *method)
	}

	links, err := scanAll(scan, bufio.NewReader(stdin), out)
	if err != nil {
		return err
	}
	showArgs := links
	if *all {
		showArgs = append([]string{"--all"}, links...)
	}
	return runShow(showArgs, nil, out)
}

// scanAll scans QR codes until every code of the export has been read.
func scanAll(scan func(macos.Runner) (string, error), in *bufio.Reader, out io.Writer) ([]string, error) {
	var links []string
	for {
		sayln(out, "Select the QR code on screen...")
		path, err := scan(macos.ExecRunner)
		if err != nil {
			return nil, err
		}
		texts, err := qrcode.ReadFile(path)
		_ = os.Remove(path)
		if err != nil {
			return nil, err
		}
		links = append(links, texts...)

		_, warnings, err := source.Load(links, nil)
		if err != nil {
			return nil, err
		}
		if len(warnings) == 0 {
			return links, nil
		}
		sayln(out, "warning:", strings.Join(warnings, "; "))
		say(out, "Press Enter to scan the next QR code, or q to continue with what was read: ")
		line, _ := in.ReadString('\n')
		if strings.TrimSpace(line) == "q" {
			return links, nil
		}
	}
}

func runInstallShortcuts(out io.Writer) error {
	if !supported() {
		return errMacOnly
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	sayln(out, "Installing shortcuts. Click \"Add Shortcut\" in each window that opens.")
	return macos.InstallShortcuts(macos.ExecRunner, exe)
}
