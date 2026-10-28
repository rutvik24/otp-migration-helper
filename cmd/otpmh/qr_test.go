package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/rutvik24/otp-migration-helper/internal/source"
)

func TestQR_PrintsEveryCodeAndTheyReadBack(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "codes")
	var out strings.Builder
	err := runQR([]string{"--all", "--per-qr", "2", "--png-dir", dir, testLink("alice", "bob", "carol")}, nil, &out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"QR code 1 of 2", "QR code 2 of 2", "Transfer accounts", "keep these secret", "█"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q:\n%.600s", want, out.String())
		}
	}

	files, err := filepath.Glob(filepath.Join(dir, "*.png"))
	if err != nil || len(files) != 2 {
		t.Fatalf("png files: %v err=%v", files, err)
	}
	sort.Strings(files)
	if info, _ := os.Stat(files[0]); info.Mode().Perm() != 0o600 && !isWindows() {
		t.Errorf("image mode %v, want 0600", info.Mode().Perm())
	}
	// The images are real Google Authenticator import codes: our own importer
	// reads them back and finds every account.
	accounts, warnings, err := source.Load(files, nil)
	if err != nil || len(accounts) != 3 || len(warnings) != 0 {
		t.Fatalf("read back: accounts=%d warnings=%v err=%v", len(accounts), warnings, err)
	}
}

func TestQR_SelectOnlySomeAccounts(t *testing.T) {
	var out strings.Builder
	if err := runQR([]string{"--select", "2", testLink("alice", "bob", "carol")}, nil, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "QR code 1 of 1") || !strings.Contains(out.String(), "1 account") {
		t.Errorf("output:\n%.400s", out.String())
	}
}

func TestQR_RejectsBadPerCodeCount(t *testing.T) {
	for _, n := range []string{"0", "11", "-3"} {
		if err := runQR([]string{"--all", "--per-qr", n, testLink("alice")}, nil, &strings.Builder{}); err == nil {
			t.Errorf("--per-qr %s should be rejected", n)
		}
	}
}

func TestQR_FromVaultAfterUnlockAndLogged(t *testing.T) {
	path := vaultPath(t)
	initPasswordVault(t, path)
	scripted(t, pw)
	runOK(t, "vault", "import", "--vault-path", path, testLink("alice", "bob"))

	scripted(t, "wrong")
	if err := runQR([]string{"--vault", "--all", "--vault-path", path}, nil, &strings.Builder{}); err == nil || err.Error() != "unlock failed" {
		t.Errorf("without the right password nothing may be shown: %v", err)
	}
	scripted(t, pw)
	var out strings.Builder
	if err := runQR([]string{"--vault", "--all", "--vault-path", path}, nil, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "QR code 1 of 1") {
		t.Errorf("output:\n%.300s", out.String())
	}
	if log := runOK(t, "vault", "log", "--vault-path", path); !strings.Contains(log, "export_qr") {
		t.Errorf("showing import codes must be logged:\n%s", log)
	}
}
