// Package macos wraps macOS-only scanning helpers: screen capture and Shortcuts.
package macos

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"howett.net/plist"
)

const (
	// ScanShortcutName is the shortcut that takes a screenshot and returns the image.
	ScanShortcutName = "OTP Migration Scan"
	// CaptureShortcutName is the shortcut that opens Terminal on the capture flow.
	CaptureShortcutName = "OTP Migration Capture"
)

// Runner runs an external command; it is replaced in tests.
type Runner func(name string, args ...string) error

func ExecRunner(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", name, err, out)
	}
	return nil
}

func Supported() bool { return supportedOS(runtime.GOOS) }

func supportedOS(goos string) bool { return goos == "darwin" }

// CaptureRegion lets the user drag a box on screen and returns the PNG path.
// The caller deletes the file.
func CaptureRegion(run Runner) (string, error) {
	return tempImage(func(path string) error {
		return run("screencapture", "-i", "-x", path)
	})
}

// RunScanShortcut runs the installed scan shortcut and returns its image output path.
func RunScanShortcut(run Runner) (string, error) {
	return tempImage(func(path string) error {
		return run("shortcuts", "run", ScanShortcutName, "--output-path", path)
	})
}

func tempImage(fill func(path string) error) (string, error) {
	f, err := os.CreateTemp("", "otpmh-*.png")
	if err != nil {
		return "", err
	}
	path := f.Name()
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	if err := fill(path); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	if info, err := os.Stat(path); err != nil || info.Size() == 0 {
		_ = os.Remove(path)
		return "", errors.New("nothing was captured")
	}
	return path, nil
}

type action struct {
	WFWorkflowActionIdentifier string
	WFWorkflowActionParameters map[string]any
}

type shortcutFile struct {
	WFWorkflowActions                 []action
	WFWorkflowClientVersion           string
	WFWorkflowMinimumClientVersion    int
	WFWorkflowTypes                   []string
	WFWorkflowImportQuestions         []any
	WFWorkflowInputContentItemClasses []string
	WFWorkflowIcon                    map[string]int
}

func newShortcut(actions ...action) shortcutFile {
	return shortcutFile{
		WFWorkflowActions:         actions,
		WFWorkflowClientVersion:   "900",
		WFWorkflowIcon:            map[string]int{"WFWorkflowIconStartColor": 4282601983, "WFWorkflowIconGlyphNumber": 59511},
		WFWorkflowTypes:           []string{},
		WFWorkflowImportQuestions: []any{},
	}
}

// InstallShortcuts builds, signs and opens both shortcuts. macOS still asks
// the user to click "Add Shortcut" for each.
func InstallShortcuts(run Runner, otpmhPath string) error {
	script := fmt.Sprintf(`osascript -e 'tell application "Terminal" to do script "%s scan --method capture"' -e 'tell application "Terminal" to activate'`, otpmhPath)
	shortcuts := map[string]shortcutFile{
		ScanShortcutName:    newShortcut(action{"is.workflow.actions.takescreenshot", map[string]any{}}),
		CaptureShortcutName: newShortcut(action{"is.workflow.actions.runshellscript", map[string]any{"Script": script, "Shell": "/bin/zsh"}}),
	}

	dir, err := os.MkdirTemp("", "otpmh-shortcuts-")
	if err != nil {
		return err
	}

	for _, name := range []string{ScanShortcutName, CaptureShortcutName} {
		unsigned := filepath.Join(dir, "unsigned-"+name+".shortcut")
		signed := filepath.Join(dir, name+".shortcut")
		data, err := plist.Marshal(shortcuts[name], plist.BinaryFormat)
		if err != nil {
			return err
		}
		if err := os.WriteFile(unsigned, data, 0o600); err != nil {
			return err
		}
		if err := run("shortcuts", "sign", "--mode", "anyone", "--input", unsigned, "--output", signed); err != nil {
			return fmt.Errorf("signing %q: %w", name, err)
		}
		if err := run("open", signed); err != nil {
			return fmt.Errorf("opening %q: %w", name, err)
		}
	}
	return nil
}
