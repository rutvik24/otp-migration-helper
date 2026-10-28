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

// scanFunc reads one round of QR codes and returns the text of each.
type scanFunc func() ([]string, error)

func runScan(args []string, stdin io.Reader, out io.Writer) error {
	if !supported() {
		return errMacOnly
	}
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(out)
	method := fs.String("method", "capture", "capture (drag a box around a QR code on screen), file (choose an image in the Finder), or shortcut (the installed Shortcuts app shortcut: camera or image file)")
	all := fs.Bool("all", false, "show every account without asking")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var scan scanFunc
	var prompt string
	switch *method {
	case "capture":
		scan, prompt = scanScreenRegion, "Select the QR code on screen..."
	case "file":
		scan, prompt = scanChosenFile, "Choose the QR code image..."
	case "shortcut":
		scan, prompt = scanWithShortcut, "Use the camera or choose an image file..."
	default:
		return fmt.Errorf("unknown method %q (use capture, file or shortcut)", *method)
	}

	links, err := scanAll(func() ([]string, error) {
		sayln(out, prompt)
		return scan()
	}, bufio.NewReader(stdin), out)
	if err != nil {
		return err
	}
	showArgs := links
	if *all {
		showArgs = append([]string{"--all"}, links...)
	}
	return runShow(showArgs, nil, out)
}

func scanScreenRegion() ([]string, error) {
	path, err := macos.CaptureRegion(macos.ExecRunner)
	if err != nil {
		return nil, err
	}
	texts, err := qrcode.ReadFile(path)
	_ = os.Remove(path) // a temporary screenshot; failing to delete it changes nothing
	return texts, err
}

func scanChosenFile() ([]string, error) {
	path, err := macos.ChooseImageFile(macos.ExecOutput)
	if err != nil {
		return nil, err
	}
	return qrcode.ReadFile(path)
}

func scanWithShortcut() ([]string, error) {
	text, err := macos.RunScanShortcut(macos.ExecRunner)
	if err != nil {
		return nil, err
	}
	return interpretShortcutOutput(text)
}

// interpretShortcutOutput turns what the scan shortcut returned into QR texts.
// Each line is either scanned QR text (otpauth links) or the path of an image
// file the user chose in the Finder, which is read for QR codes.
func interpretShortcutOutput(output string) ([]string, error) {
	var texts []string
	seen := map[string]bool{}
	add := func(t string) {
		if !seen[t] {
			seen[t] = true
			texts = append(texts, t)
		}
	}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
		case strings.HasPrefix(line, "otpauth://") || strings.HasPrefix(line, "otpauth-migration://"):
			add(line)
		default:
			if _, err := os.Stat(line); err != nil {
				return nil, fmt.Errorf("the shortcut returned %.40q, which is not a QR code or an image file", line)
			}
			found, err := qrcode.ReadFile(line)
			if err != nil {
				return nil, err
			}
			for _, t := range found {
				add(t)
			}
		}
	}
	if len(texts) == 0 {
		return nil, errors.New("the shortcut returned no QR codes; the result is not a QR code")
	}
	return texts, nil
}

// scanAll scans QR codes until every code of the export has been read.
func scanAll(scan scanFunc, in *bufio.Reader, out io.Writer) ([]string, error) {
	var links []string
	for {
		texts, err := scan()
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
	if err := macos.InstallShortcuts(macos.ExecRunner, exe); err != nil {
		return err
	}
	sayln(out, "Installed:")
	say(out, "  %s: scan with the camera or choose an image file in the Finder.\n    Use it with: otpmh scan --method shortcut\n", macos.ScanShortcutName)
	say(out, "  %s: opens Terminal to select a QR code anywhere on screen.\n", macos.CaptureShortcutName)
	return nil
}
