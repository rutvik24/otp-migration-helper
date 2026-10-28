package main

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/rutvik24/otp-migration-helper/internal/prompt"
	"github.com/rutvik24/otp-migration-helper/internal/vaultcrypto"
)

func TestMain(m *testing.M) {
	vaultcrypto.SetWorkFactorForTests(10)
	os.Exit(m.Run())
}

// scripted replaces the secret prompt with a queue of answers.
func scripted(t *testing.T, answers ...string) {
	t.Helper()
	old := prompt.Secret
	t.Cleanup(func() { prompt.Secret = old })
	prompt.Secret = func(string) (string, error) {
		if len(answers) == 0 {
			return "", errors.New("unexpected prompt")
		}
		a := answers[0]
		answers = answers[1:]
		return a, nil
	}
}

const (
	pw      = "correct horse"
	recPass = "recovery-passphrase-1"
)

func vaultPath(t *testing.T) string {
	return filepath.Join(t.TempDir(), "vault.db")
}

func runOK(t *testing.T, args ...string) string {
	t.Helper()
	var out strings.Builder
	if err := run(args, strings.NewReader(""), &out); err != nil {
		t.Fatalf("%v: %v", args, err)
	}
	return out.String()
}

func initPasswordVault(t *testing.T, path string) string {
	t.Helper()
	scripted(t, pw, pw, recPass, recPass)
	return runOK(t, "vault", "init", "--unlock", "password", "--vault-path", path)
}

func TestVaultInit_PasswordThenList(t *testing.T) {
	path := vaultPath(t)
	initPasswordVault(t, path)

	scripted(t, pw)
	runOK(t, "vault", "import", "--vault-path", path, testLink("alice"))
	scripted(t, pw)
	if out := runOK(t, "vault", "list", "--vault-path", path); !strings.Contains(out, "alice") {
		t.Errorf("list output: %s", out)
	}
}

func TestVaultInit_PasswordMismatchErrors(t *testing.T) {
	scripted(t, pw, "different")
	var out strings.Builder
	err := run([]string{"vault", "init", "--unlock", "password", "--vault-path", vaultPath(t)}, nil, &out)
	if err == nil {
		t.Error("expected error")
	}
}

func TestVaultInit_PrintsRecoveryCodeOnce(t *testing.T) {
	out := initPasswordVault(t, vaultPath(t))
	codes := regexp.MustCompile(`([A-Z2-7]{4}-){7}[A-Z2-7]{4}`).FindAllString(out, -1)
	if len(codes) != 1 {
		t.Errorf("want exactly one recovery code, got %d in:\n%s", len(codes), out)
	}
}

func TestVaultInit_NoRecoveryWarns(t *testing.T) {
	scripted(t, pw, pw)
	out := runOK(t, "vault", "init", "--unlock", "password", "--no-recovery", "--vault-path", vaultPath(t))
	if !strings.Contains(out, "cannot be recovered") {
		t.Errorf("missing warning:\n%s", out)
	}
}

func TestVaultImport_TwiceAddsOnce(t *testing.T) {
	path := vaultPath(t)
	initPasswordVault(t, path)
	scripted(t, pw)
	if out := runOK(t, "vault", "import", "--vault-path", path, testLink("alice")); !strings.Contains(out, "added 1") {
		t.Errorf("first import: %s", out)
	}
	scripted(t, pw)
	if out := runOK(t, "vault", "import", "--vault-path", path, testLink("alice")); !strings.Contains(out, "added 0") {
		t.Errorf("second import: %s", out)
	}
}

func TestVaultList_WrongPasswordGenericError(t *testing.T) {
	path := vaultPath(t)
	initPasswordVault(t, path)
	scripted(t, "wrong")
	var out strings.Builder
	err := run([]string{"vault", "list", "--vault-path", path}, nil, &out)
	if err == nil || err.Error() != "unlock failed" {
		t.Errorf("err: %v", err)
	}
}

func TestVaultLog_NoSecrets(t *testing.T) {
	path := vaultPath(t)
	initPasswordVault(t, path)
	scripted(t, pw)
	runOK(t, "vault", "import", "--vault-path", path, testLink("alice"))
	scripted(t, "wrong")
	_ = run([]string{"vault", "list", "--vault-path", path}, nil, &strings.Builder{})

	out := runOK(t, "vault", "log", "--vault-path", path)
	for _, secret := range []string{"GEZDGNBVGY3TQOJQ", "12345678901234567890", pw, recPass} {
		if strings.Contains(out, secret) {
			t.Errorf("log leaks %q:\n%s", secret, out)
		}
	}
	for _, action := range []string{"create", "import", "unlock_failed"} {
		if !strings.Contains(out, action) {
			t.Errorf("log missing %q:\n%s", action, out)
		}
	}
}
