// Package macos wraps macOS-only scanning helpers: screen capture and Shortcuts.
package macos

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

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

// OutputRunner runs an external command and returns what it printed.
type OutputRunner func(name string, args ...string) ([]byte, error)

func ExecOutput(name string, args ...string) ([]byte, error) {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return out, fmt.Errorf("%s: %w: %s", name, err, exit.Stderr)
		}
		return out, fmt.Errorf("%s: %w", name, err)
	}
	return out, nil
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

// RunScanShortcut runs the installed scan shortcut, which asks whether to use
// the camera or to choose an image file, and returns what it produced: the
// scanned QR text, or the path of the chosen image.
func RunScanShortcut(run Runner) (string, error) {
	f, err := os.CreateTemp("", "otpmh-scan-*.txt")
	if err != nil {
		return "", err
	}
	path := f.Name()
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	defer func() { _ = os.Remove(path) }()

	if err := run("shortcuts", "run", ScanShortcutName, "--output-path", path, "--output-type", "public.plain-text"); err != nil {
		return "", fmt.Errorf("could not run the %q shortcut (is it installed? run otpmh install-shortcuts): %w", ScanShortcutName, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	text := strings.TrimSpace(string(data))
	if text == "" {
		return "", fmt.Errorf("the %q shortcut returned nothing; run otpmh install-shortcuts to add it, then choose Add Shortcut", ScanShortcutName)
	}
	return text, nil
}

// ChooseImageFile opens the Finder's file chooser for an image and returns its path.
func ChooseImageFile(out OutputRunner) (string, error) {
	const script = `POSIX path of (choose file with prompt "Choose the QR code image" of type {"public.image"})`
	data, err := out("osascript", "-e", script)
	if err != nil {
		if strings.Contains(err.Error(), "canceled") || strings.Contains(string(data), "canceled") {
			return "", errors.New("cancelled: no file was chosen")
		}
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
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
	WFWorkflowActions                    []action
	WFWorkflowClientVersion              string
	WFWorkflowMinimumClientVersion       int
	WFWorkflowMinimumClientVersionString string
	WFWorkflowTypes                      []string
	WFWorkflowImportQuestions            []any
	WFWorkflowInputContentItemClasses    []string
	WFWorkflowOutputContentItemClasses   []string
	WFWorkflowHasOutputFallback          bool
	WFWorkflowHasShortcutInputVariables  bool
	WFQuickActionSurfaces                []string
	WFWorkflowIcon                       map[string]int64
}

// newShortcut fills in the same top-level settings as a shortcut exported by
// the Shortcuts app itself.
func newShortcut(actions ...action) shortcutFile {
	return shortcutFile{
		WFWorkflowActions:                    actions,
		WFWorkflowClientVersion:              "1505.1",
		WFWorkflowMinimumClientVersion:       900,
		WFWorkflowMinimumClientVersionString: "900",
		WFWorkflowIcon:                       map[string]int64{"WFWorkflowIconStartColor": 4282601983, "WFWorkflowIconGlyphNumber": 59401},
		WFWorkflowTypes:                      []string{"WFWorkflowTypeShowInSearch"},
		WFWorkflowImportQuestions:            []any{},
		WFWorkflowInputContentItemClasses:    []string{},
		WFWorkflowOutputContentItemClasses:   []string{},
		WFQuickActionSurfaces:                []string{},
	}
}

const (
	actionMenu       = "is.workflow.actions.choosefrommenu"
	actionScan       = "is.workflow.actions.scanbarcode" // the camera scanner, as in Apple's own "Scan QR code" example
	actionShell      = "is.workflow.actions.runshellscript"
	menuGroup        = "6B1F5C0E-3A5D-4B7E-9C21-8D4E7A9F2B10"
	menuEndID        = "A0D3C7E1-52B4-4F86-B1C9-7E2F6D8A3C45"
	scanActionID     = "F4E2B9A7-1C63-4D58-8A0B-3C9E5D7F1A26"
	fileActionID     = "C8A5E3D1-9B27-4F60-A4E8-1D6B2F7C9E03"
	menuCameraTitle  = "Scan with the camera"
	menuFileTitle    = "Choose an image file"
	chooseFileScript = `osascript -e 'POSIX path of (choose file with prompt "Choose the QR code image" of type {"public.image"})'`
)

func menuAction(mode int, extra map[string]any) action {
	params := map[string]any{"GroupingIdentifier": menuGroup, "WFControlFlowMode": mode}
	for k, v := range extra {
		params[k] = v
	}
	return action{actionMenu, params}
}

// scanShortcut asks whether to use the camera or an image file, then returns
// the scanned QR text or the chosen image's path to otpmh.
func scanShortcut() shortcutFile {
	return newShortcut(
		menuAction(0, map[string]any{"WFMenuPrompt": "Scan a QR code", "WFMenuItems": []string{menuCameraTitle, menuFileTitle}}),
		menuAction(1, map[string]any{"WFMenuItemTitle": menuCameraTitle}),
		action{actionScan, map[string]any{"UUID": scanActionID}},
		menuAction(1, map[string]any{"WFMenuItemTitle": menuFileTitle}),
		action{actionShell, map[string]any{"UUID": fileActionID, "Script": chooseFileScript, "Shell": "/bin/zsh"}},
		menuAction(2, map[string]any{"UUID": menuEndID}),
	)
}

// InstallShortcuts builds, signs and opens both shortcuts. macOS still asks
// the user to click "Add Shortcut" for each.
func InstallShortcuts(run Runner, otpmhPath string) error {
	script := fmt.Sprintf(`osascript -e 'tell application "Terminal" to do script "%s scan --method capture"' -e 'tell application "Terminal" to activate'`, otpmhPath)
	shortcuts := map[string]shortcutFile{
		ScanShortcutName:    scanShortcut(),
		CaptureShortcutName: newShortcut(action{actionShell, map[string]any{"Script": script, "Shell": "/bin/zsh"}}),
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
