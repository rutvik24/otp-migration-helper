package store

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/rutvik24/otp-migration-helper/internal/migration"
	"github.com/rutvik24/otp-migration-helper/internal/otp"
	"github.com/rutvik24/otp-migration-helper/internal/vaultcrypto"
)

var secret = []byte("very-distinct-secret-bytes-123")

func newStore(t *testing.T) (*Store, string, []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault.db")
	key, err := vaultcrypto.NewDataKey()
	if err != nil {
		t.Fatal(err)
	}
	s, err := Create(path, vaultcrypto.Wrapped{Mode: vaultcrypto.Password, Password: []byte("blob")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path, key
}

func account(name string) migration.Account {
	return migration.Account{Name: name, Issuer: "Acme", Secret: secret, Algorithm: otp.SHA256, Digits: 8, Kind: migration.HOTP, Counter: 3}
}

func TestCreate_Mode0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file modes are not supported on Windows")
	}
	_, path, _ := newStore(t)
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v err %v", info.Mode(), err)
	}
}

func TestCreate_ExistingFileErrors(t *testing.T) {
	_, path, _ := newStore(t)
	if _, err := Create(path, vaultcrypto.Wrapped{}); err == nil {
		t.Error("expected error")
	}
}

func TestWrapped_RoundTripAndSet(t *testing.T) {
	s, _, _ := newStore(t)
	w, err := s.Wrapped()
	if err != nil || w.Mode != vaultcrypto.Password || string(w.Password) != "blob" {
		t.Fatalf("w=%+v err=%v", w, err)
	}
	if err := s.SetWrapped(vaultcrypto.Wrapped{Mode: vaultcrypto.SSH, SSH: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if w, _ = s.Wrapped(); w.Mode != vaultcrypto.SSH {
		t.Errorf("not updated: %+v", w)
	}
}

func TestAddAccounts_RoundTrip(t *testing.T) {
	s, _, key := newStore(t)
	if n, err := s.AddAccounts(key, []migration.Account{account("a"), account("b")}); err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	recs, err := s.Accounts(key)
	if err != nil || len(recs) != 2 {
		t.Fatalf("recs=%d err=%v", len(recs), err)
	}
	got := recs[0]
	if got.Name != "a" || got.Issuer != "Acme" || !bytes.Equal(got.Secret, secret) || got.Algorithm != otp.SHA256 || got.Digits != 8 || got.Kind != migration.HOTP || got.Counter != 3 || got.ID == 0 {
		t.Errorf("unexpected %+v", got)
	}
}

func TestAddAccounts_Dedupes(t *testing.T) {
	s, _, key := newStore(t)
	if _, err := s.AddAccounts(key, []migration.Account{account("a")}); err != nil {
		t.Fatal(err)
	}
	n, err := s.AddAccounts(key, []migration.Account{account("a"), account("b")})
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestSecretNotPlaintextOnDisk(t *testing.T) {
	s, path, key := newStore(t)
	if _, err := s.AddAccounts(key, []migration.Account{account("a")}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, secret) {
		t.Error("secret found in plaintext on disk")
	}
}

func TestSetCounter_Persists(t *testing.T) {
	s, path, key := newStore(t)
	if _, err := s.AddAccounts(key, []migration.Account{account("a")}); err != nil {
		t.Fatal(err)
	}
	recs, _ := s.Accounts(key)
	if err := s.SetCounter(recs[0].ID, 9); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s2.Close() }()
	if recs, _ = s2.Accounts(key); recs[0].Counter != 9 {
		t.Errorf("counter %d", recs[0].Counter)
	}
}

func TestLog_Order(t *testing.T) {
	s, _, _ := newStore(t)
	for _, a := range []string{"first", "second"} {
		if err := s.Log(a, "detail"); err != nil {
			t.Fatal(err)
		}
	}
	logs, err := s.Logs()
	if err != nil || len(logs) != 2 || logs[0].Action != "first" || logs[1].Detail != "detail" {
		t.Fatalf("logs=%+v err=%v", logs, err)
	}
}

func TestRecoveryLockout(t *testing.T) {
	s, _, _ := newStore(t)
	now := time.Unix(1_000_000, 0)
	for i := 1; i <= 4; i++ {
		if err := s.RecordRecoveryFailure(now); err != nil {
			t.Fatal(err)
		}
	}
	if f, locked, _ := s.RecoveryState(); f != 4 || locked.After(now) {
		t.Errorf("failures=%d locked=%v", f, locked)
	}
	if err := s.RecordRecoveryFailure(now); err != nil {
		t.Fatal(err)
	}
	if f, locked, _ := s.RecoveryState(); f != 5 || !locked.Equal(now.Add(24*time.Hour)) {
		t.Errorf("failures=%d locked=%v", f, locked)
	}
	if err := s.ClearRecoveryFailures(); err != nil {
		t.Fatal(err)
	}
	if f, locked, _ := s.RecoveryState(); f != 0 || locked.After(now) {
		t.Errorf("not cleared: %d %v", f, locked)
	}
}

func TestRekey_OldKeyFailsNewKeyWorks(t *testing.T) {
	s, _, oldKey := newStore(t)
	if _, err := s.AddAccounts(oldKey, []migration.Account{account("a")}); err != nil {
		t.Fatal(err)
	}
	newKey, err := vaultcrypto.NewDataKey()
	if err != nil {
		t.Fatal(err)
	}
	w := vaultcrypto.Wrapped{Mode: vaultcrypto.SSH, SSH: []byte("rewrapped")}
	if err := s.Rekey(oldKey, newKey, w); err != nil {
		t.Fatal(err)
	}

	if _, err := s.Accounts(oldKey); err == nil {
		t.Error("old key still decrypts rows")
	}
	recs, err := s.Accounts(newKey)
	if err != nil || len(recs) != 1 || !bytes.Equal(recs[0].Secret, secret) {
		t.Fatalf("recs=%+v err=%v", recs, err)
	}
	if got, _ := s.Wrapped(); got.Mode != vaultcrypto.SSH {
		t.Errorf("wrapped not updated: %+v", got)
	}
	if n, err := s.AddAccounts(newKey, []migration.Account{account("a")}); err != nil || n != 0 {
		t.Errorf("dedupe broken after rekey: n=%d err=%v", n, err)
	}
}

func TestRekey_WrongOldKeyChangesNothing(t *testing.T) {
	s, _, key := newStore(t)
	if _, err := s.AddAccounts(key, []migration.Account{account("a")}); err != nil {
		t.Fatal(err)
	}
	wrong, _ := vaultcrypto.NewDataKey()
	fresh, _ := vaultcrypto.NewDataKey()
	if err := s.Rekey(wrong, fresh, vaultcrypto.Wrapped{Mode: vaultcrypto.SSH}); err == nil {
		t.Fatal("expected error")
	}
	if _, err := s.Accounts(key); err != nil {
		t.Errorf("rows changed after failed rekey: %v", err)
	}
	if got, _ := s.Wrapped(); got.Mode != vaultcrypto.Password {
		t.Errorf("wrapped changed after failed rekey: %+v", got)
	}
}
