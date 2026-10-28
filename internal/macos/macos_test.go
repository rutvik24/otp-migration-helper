package macos

import (
	"errors"
	"strings"
	"testing"
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
