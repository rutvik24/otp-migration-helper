package macos

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"howett.net/plist"
)

var errFake = errors.New("fake")

func TestSupportedOS(t *testing.T) {
	if !supportedOS("darwin") || supportedOS("linux") || supportedOS("windows") {
		t.Error("only darwin should be supported")
	}
}

func TestInstall_SignsThenOpens(t *testing.T) {
	var calls []string
	run := func(name string, args ...string) error {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil
	}
	if err := InstallShortcuts(run, "otpmh"); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 4 {
		t.Fatalf("calls: %v", calls)
	}
	for i := 0; i < len(calls); i += 2 {
		if !strings.HasPrefix(calls[i], "shortcuts sign --mode anyone") || !strings.HasPrefix(calls[i+1], "open ") {
			t.Errorf("want sign then open, got %q then %q", calls[i], calls[i+1])
		}
	}
}

func TestInstall_StopsOnSignError(t *testing.T) {
	run := func(name string, args ...string) error { return errFake }
	if err := InstallShortcuts(run, "otpmh"); err == nil {
		t.Error("expected error")
	}
}

// signedInputs runs the installer with a recording runner and returns the
// unsigned shortcut files it handed to `shortcuts sign`, by shortcut name.
func signedInputs(t *testing.T) map[string]shortcutFile {
	t.Helper()
	got := map[string]shortcutFile{}
	run := func(name string, args ...string) error {
		if name == "shortcuts" && len(args) > 0 && args[0] == "sign" {
			for i, a := range args {
				if a != "--input" {
					continue
				}
				data, err := os.ReadFile(args[i+1])
				if err != nil {
					t.Fatal(err)
				}
				var sc shortcutFile
				if _, err := plist.Unmarshal(data, &sc); err != nil {
					t.Fatalf("shortcut is not a valid property list: %v", err)
				}
				for _, n := range []string{ScanShortcutName, CaptureShortcutName} {
					if strings.Contains(args[i+1], n) {
						got[n] = sc
					}
				}
			}
		}
		return nil
	}
	if err := InstallShortcuts(run, "/usr/local/bin/otpmh"); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestInstall_ScanShortcutOffersCameraAndFileNotScreenshot(t *testing.T) {
	sc, ok := signedInputs(t)[ScanShortcutName]
	if !ok {
		t.Fatal("scan shortcut was not installed")
	}
	var ids []string
	var modes []int
	var groups = map[string]bool{}
	var script string
	for _, a := range sc.WFWorkflowActions {
		ids = append(ids, a.WFWorkflowActionIdentifier)
		if a.WFWorkflowActionIdentifier == "is.workflow.actions.choosefrommenu" {
			modes = append(modes, int(a.WFWorkflowActionParameters["WFControlFlowMode"].(uint64)))
			groups[a.WFWorkflowActionParameters["GroupingIdentifier"].(string)] = true
		}
		if a.WFWorkflowActionIdentifier == "is.workflow.actions.runshellscript" {
			script, _ = a.WFWorkflowActionParameters["Script"].(string)
		}
	}
	want := []string{
		"is.workflow.actions.choosefrommenu", "is.workflow.actions.choosefrommenu", "is.workflow.actions.scanbarcode",
		"is.workflow.actions.choosefrommenu", "is.workflow.actions.runshellscript", "is.workflow.actions.choosefrommenu",
	}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Errorf("actions:\n got %v\nwant %v", ids, want)
	}
	if fmt.Sprint(modes) != "[0 1 1 2]" || len(groups) != 1 {
		t.Errorf("menu must be one start, two cases and one end sharing a group: modes=%v groups=%d", modes, len(groups))
	}
	for _, id := range ids {
		if strings.Contains(id, "screenshot") {
			t.Error("the scan shortcut must not take a whole-screen screenshot")
		}
	}
	if !strings.Contains(script, "choose file") || !strings.Contains(script, "public.image") {
		t.Errorf("the file step must open a Finder file chooser for images: %q", script)
	}
	menu := sc.WFWorkflowActions[0].WFWorkflowActionParameters["WFMenuItems"].([]any)
	if len(menu) != 2 {
		t.Errorf("menu items: %v", menu)
	}
	for i, idx := range []int{1, 3} {
		if sc.WFWorkflowActions[idx].WFWorkflowActionParameters["WFMenuItemTitle"] != menu[i] {
			t.Errorf("case %d title does not match its menu item", i)
		}
	}
}

func TestRunScanShortcut_ReturnsTheScannedText(t *testing.T) {
	var gotArgs []string
	run := func(name string, args ...string) error {
		gotArgs = args
		for i, a := range args {
			if a == "--output-path" {
				return os.WriteFile(args[i+1], []byte("otpauth-migration://offline?data=abc\n"), 0o600)
			}
		}
		return errors.New("no output path")
	}
	text, err := RunScanShortcut(run)
	if err != nil || text != "otpauth-migration://offline?data=abc" {
		t.Fatalf("text=%q err=%v", text, err)
	}
	if !strings.Contains(strings.Join(gotArgs, " "), "run "+ScanShortcutName) || !strings.Contains(strings.Join(gotArgs, " "), "--output-type public.plain-text") {
		t.Errorf("args: %v", gotArgs)
	}
}

func TestRunScanShortcut_NothingReturnedIsAnError(t *testing.T) {
	run := func(name string, args ...string) error { return nil }
	if _, err := RunScanShortcut(run); err == nil || !strings.Contains(err.Error(), "install-shortcuts") {
		t.Errorf("should point at install-shortcuts: %v", err)
	}
}

func TestChooseImageFile(t *testing.T) {
	ok := func(name string, args ...string) ([]byte, error) {
		if name != "osascript" || !strings.Contains(strings.Join(args, " "), "choose file") {
			t.Errorf("unexpected command %s %v", name, args)
		}
		return []byte("/Users/me/My QR.png\n"), nil
	}
	if path, err := ChooseImageFile(ok); err != nil || path != "/Users/me/My QR.png" {
		t.Errorf("path=%q err=%v", path, err)
	}
	cancelled := func(string, ...string) ([]byte, error) {
		return []byte("execution error: User canceled. (-128)"), errFake
	}
	if _, err := ChooseImageFile(cancelled); err == nil || !strings.Contains(err.Error(), "cancel") {
		t.Errorf("cancel: %v", err)
	}
}
