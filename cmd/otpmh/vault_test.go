package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"google.golang.org/protobuf/encoding/protowire"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
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

func hotpLink(name string) string {
	var acct []byte
	acct = protowire.AppendTag(acct, 1, protowire.BytesType)
	acct = protowire.AppendBytes(acct, []byte("12345678901234567890"))
	acct = protowire.AppendTag(acct, 2, protowire.BytesType)
	acct = protowire.AppendString(acct, name)
	acct = protowire.AppendTag(acct, 6, protowire.VarintType)
	acct = protowire.AppendVarint(acct, 1)
	acct = protowire.AppendTag(acct, 7, protowire.VarintType)
	acct = protowire.AppendVarint(acct, 4)
	var payload []byte
	payload = protowire.AppendTag(payload, 1, protowire.BytesType)
	payload = protowire.AppendBytes(payload, acct)
	return "otpauth-migration://offline?data=" + url.QueryEscape(base64.StdEncoding.EncodeToString(payload))
}

func TestShow_FromVault(t *testing.T) {
	path := vaultPath(t)
	initPasswordVault(t, path)
	scripted(t, pw)
	runOK(t, "vault", "import", "--vault-path", path, testLink("alice"))

	scripted(t, pw)
	out := runOK(t, "show", "--vault", "--all", "--vault-path", path)
	if !strings.Contains(out, "otpauth://totp/alice") {
		t.Errorf("output:\n%s", out)
	}
}

func TestVaultHotpCounterPersists(t *testing.T) {
	path := vaultPath(t)
	initPasswordVault(t, path)
	scripted(t, pw)
	runOK(t, "vault", "import", "--vault-path", path, hotpLink("hotp"))

	scripted(t, pw)
	s, key, err := openVault(&vaultFlags{path: path})
	if err != nil {
		t.Fatal(err)
	}
	recs, err := s.Accounts(key)
	if err != nil || recs[0].Counter != 4 {
		t.Fatalf("recs=%+v err=%v", recs, err)
	}
	if err := counterSaver(s, recs)(0, 5); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	scripted(t, pw)
	s, key, err = openVault(&vaultFlags{path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if recs, _ = s.Accounts(key); recs[0].Counter != 5 {
		t.Errorf("counter %d, want 5", recs[0].Counter)
	}
}

func TestVaultExport_RequiresYes(t *testing.T) {
	path := vaultPath(t)
	initPasswordVault(t, path)
	scripted(t, pw)
	runOK(t, "vault", "import", "--vault-path", path, testLink("alice"))

	outFile := filepath.Join(t.TempDir(), "export.json")
	scripted(t, pw)
	err := run([]string{"vault", "export", "--format", "bitwarden", "--out", outFile, "--vault-path", path}, nil, &strings.Builder{})
	if err == nil {
		t.Error("expected error without --yes")
	}
	if _, statErr := os.Stat(outFile); statErr == nil {
		t.Error("file written without --yes")
	}
}

func TestVaultExport_FileMode0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file modes are not supported on Windows")
	}
	path := vaultPath(t)
	initPasswordVault(t, path)
	scripted(t, pw)
	runOK(t, "vault", "import", "--vault-path", path, testLink("alice"))

	outFile := filepath.Join(t.TempDir(), "export.json")
	scripted(t, pw)
	runOK(t, "vault", "export", "--format", "bitwarden", "--yes", "--out", outFile, "--vault-path", path)
	info, err := os.Stat(outFile)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v err %v", info, err)
	}
	data, _ := os.ReadFile(outFile)
	if !strings.Contains(string(data), "otpauth://totp/alice") {
		t.Errorf("export: %s", data)
	}
}

func TestVaultExport_UnknownFormat(t *testing.T) {
	path := vaultPath(t)
	initPasswordVault(t, path)
	scripted(t, pw)
	err := run([]string{"vault", "export", "--format", "nope", "--yes", "--vault-path", path}, nil, &strings.Builder{})
	if err == nil {
		t.Error("expected error")
	}
}

var recoveryCodeRe = regexp.MustCompile(`([A-Z2-7]{4}-){7}[A-Z2-7]{4}`)

func recoveryCodeIn(t *testing.T, out string) string {
	t.Helper()
	code := recoveryCodeRe.FindString(out)
	if code == "" {
		t.Fatalf("no recovery code in:\n%s", out)
	}
	return code
}

func recoverErr(path string) error {
	return run([]string{"vault", "recover", "--unlock", "password", "--vault-path", path}, nil, &strings.Builder{})
}

func TestRecover_Success(t *testing.T) {
	path := vaultPath(t)
	code := recoveryCodeIn(t, initPasswordVault(t, path))
	scripted(t, pw)
	runOK(t, "vault", "import", "--vault-path", path, testLink("alice"))

	scripted(t, code, recPass, "new password", "new password", "new-recovery-pass-2", "new-recovery-pass-2")
	out := runOK(t, "vault", "recover", "--unlock", "password", "--vault-path", path)
	if newCode := recoveryCodeIn(t, out); newCode == code {
		t.Error("recovery code was not rotated")
	}

	scripted(t, "new password")
	if out := runOK(t, "vault", "list", "--vault-path", path); !strings.Contains(out, "alice") {
		t.Errorf("accounts lost after recovery: %s", out)
	}
	scripted(t, pw)
	if err := run([]string{"vault", "list", "--vault-path", path}, nil, &strings.Builder{}); err == nil {
		t.Error("old password still works")
	}
}

func TestRecover_OldRecoveryCodeDead(t *testing.T) {
	path := vaultPath(t)
	code := recoveryCodeIn(t, initPasswordVault(t, path))
	scripted(t, code, recPass, pw, pw, "new-recovery-pass-2", "new-recovery-pass-2")
	runOK(t, "vault", "recover", "--unlock", "password", "--vault-path", path)

	scripted(t, code, recPass, pw, pw, "new-recovery-pass-3", "new-recovery-pass-3")
	if err := recoverErr(path); err == nil || err.Error() != "recovery failed" {
		t.Errorf("old code accepted: %v", err)
	}
}

func TestRecover_WrongCodeWrongPassphraseSameMessage(t *testing.T) {
	path := vaultPath(t)
	code := recoveryCodeIn(t, initPasswordVault(t, path))
	cases := [][2]string{{"AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA", recPass}, {code, "not-the-passphrase"}, {"BBBB-BBBB-BBBB-BBBB-BBBB-BBBB-BBBB-BBBB", "not-the-passphrase"}}
	for _, c := range cases {
		scripted(t, c[0], c[1])
		if err := recoverErr(path); err == nil || err.Error() != "recovery failed" {
			t.Errorf("code=%q: err=%v", c[0], err)
		}
	}
}

func TestRecover_LockoutAfterFiveFailures(t *testing.T) {
	path := vaultPath(t)
	code := recoveryCodeIn(t, initPasswordVault(t, path))
	for i := 0; i < 5; i++ {
		scripted(t, "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA", recPass)
		if err := recoverErr(path); err == nil {
			t.Fatal("expected failure")
		}
	}
	scripted(t, code, recPass, pw, pw, "new-recovery-pass-2", "new-recovery-pass-2")
	if err := recoverErr(path); err == nil || err.Error() != "recovery failed" {
		t.Errorf("correct secrets accepted while locked: %v", err)
	}
}

func TestRecover_NoRecoveryVault(t *testing.T) {
	path := vaultPath(t)
	scripted(t, pw, pw)
	runOK(t, "vault", "init", "--unlock", "password", "--no-recovery", "--vault-path", path)
	scripted(t, "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA", recPass)
	if err := recoverErr(path); err == nil || err.Error() != "recovery failed" {
		t.Errorf("err: %v", err)
	}
}

func TestRecover_LogsNoSecrets(t *testing.T) {
	path := vaultPath(t)
	code := recoveryCodeIn(t, initPasswordVault(t, path))
	scripted(t, "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA", recPass)
	_ = recoverErr(path)
	scripted(t, code, recPass, "new password", "new password", "new-recovery-pass-2", "new-recovery-pass-2")
	runOK(t, "vault", "recover", "--unlock", "password", "--vault-path", path)

	out := runOK(t, "vault", "log", "--vault-path", path)
	for _, secret := range []string{code, recPass, pw, "new password", "new-recovery-pass-2", "AAAA-AAAA"} {
		if strings.Contains(out, secret) {
			t.Errorf("log leaks %q:\n%s", secret, out)
		}
	}
	for _, action := range []string{"recovery_failed", "recovery"} {
		if !strings.Contains(out, action) {
			t.Errorf("log missing %q:\n%s", action, out)
		}
	}
}

func TestRecover_ReEncryptsRowsUnderNewKey(t *testing.T) {
	path := vaultPath(t)
	code := recoveryCodeIn(t, initPasswordVault(t, path))
	scripted(t, pw)
	runOK(t, "vault", "import", "--vault-path", path, testLink("alice"))

	scripted(t, pw)
	s, oldKey, err := openVault(&vaultFlags{path: path})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	scripted(t, code, recPass, "new password", "new password", "new-recovery-pass-2", "new-recovery-pass-2")
	runOK(t, "vault", "recover", "--unlock", "password", "--vault-path", path)

	scripted(t, "new password")
	s, newKey, err := openVault(&vaultFlags{path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if bytes.Equal(oldKey, newKey) {
		t.Error("data key was not rotated")
	}
	if _, err := s.Accounts(oldKey); err == nil {
		t.Error("old data key still decrypts the rows")
	}
	if recs, err := s.Accounts(newKey); err != nil || len(recs) != 1 {
		t.Errorf("recs=%v err=%v", recs, err)
	}
}
