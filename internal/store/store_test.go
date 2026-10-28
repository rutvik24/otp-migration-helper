package store

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

func testWrappedRoundTripAndSet(t *testing.T, mk maker) {
	s, _, _ := mk(t)
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

func testAddAccountsRoundTrip(t *testing.T, mk maker) {
	s, _, key := mk(t)
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

func testAddAccountsDedupes(t *testing.T, mk maker) {
	s, _, key := mk(t)
	if _, err := s.AddAccounts(key, []migration.Account{account("a")}); err != nil {
		t.Fatal(err)
	}
	n, err := s.AddAccounts(key, []migration.Account{account("a"), account("b")})
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func testSecretNotStoredInPlaintext(t *testing.T, mk maker) {
	s, _, key := mk(t)
	if _, err := s.AddAccounts(key, []migration.Account{account("a")}); err != nil {
		t.Fatal(err)
	}
	var stored []byte
	if err := s.QueryRow(`SELECT secret FROM accounts`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, secret) {
		t.Error("secret column holds the plaintext secret")
	}
}

func TestSecretNotPlaintextInSQLiteFile(t *testing.T) {
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

func testSetCounterPersists(t *testing.T, mk maker) {
	s, target, key := mk(t)
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
	s2, err := Open(target)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s2.Close() }()
	if recs, _ = s2.Accounts(key); recs[0].Counter != 9 {
		t.Errorf("counter %d", recs[0].Counter)
	}
}

func testLogOrder(t *testing.T, mk maker) {
	s, _, _ := mk(t)
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

func testRecoveryLockout(t *testing.T, mk maker) {
	s, _, _ := mk(t)
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

func testRekeyOldKeyFailsNewKeyWorks(t *testing.T, mk maker) {
	s, _, oldKey := mk(t)
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

func testRekeyWrongOldKeyChangesNothing(t *testing.T, mk maker) {
	s, _, key := mk(t)
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

// ---------- every backend ----------

type maker func(t *testing.T) (*Store, string, []byte)

// backends returns SQLite always, and PostgreSQL / MySQL when a test server's
// URL is given in OTPMH_TEST_POSTGRES_URL / OTPMH_TEST_MYSQL_URL.
func backends(t *testing.T) map[string]maker {
	t.Helper()
	all := map[string]maker{"sqlite": newStore}
	for name, env := range map[string]string{"postgres": "OTPMH_TEST_POSTGRES_URL", "mysql": "OTPMH_TEST_MYSQL_URL"} {
		if target := os.Getenv(env); target != "" {
			all[name] = serverMaker(target)
		}
	}
	return all
}

// serverMaker starts every test from empty tables on a shared test database.
func serverMaker(target string) maker {
	return func(t *testing.T) (*Store, string, []byte) {
		t.Helper()
		dropTables(t, target)
		key, err := vaultcrypto.NewDataKey()
		if err != nil {
			t.Fatal(err)
		}
		s, err := Create(target, vaultcrypto.Wrapped{Mode: vaultcrypto.Password, Password: []byte("blob")})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close() })
		return s, target, key
	}
}

func dropTables(t *testing.T, target string) {
	t.Helper()
	if err := DropForTests(target); err != nil {
		t.Fatal(err)
	}
}

func TestBackends(t *testing.T) {
	suite := map[string]func(*testing.T, maker){
		"rapped_RoundTripAndSet":         testWrappedRoundTripAndSet,
		"ddAccounts_RoundTrip":           testAddAccountsRoundTrip,
		"ddAccounts_Dedupes":             testAddAccountsDedupes,
		"etCounter_Persists":             testSetCounterPersists,
		"og_Order":                       testLogOrder,
		"ecoveryLockout":                 testRecoveryLockout,
		"ekey_OldKeyFailsNewKeyWorks":    testRekeyOldKeyFailsNewKeyWorks,
		"ekey_WrongOldKeyChangesNothing": testRekeyWrongOldKeyChangesNothing,
		"SecretNotStoredInPlaintext":     testSecretNotStoredInPlaintext,
	}
	for backend, mk := range backends(t) {
		for name, run := range suite {
			t.Run(backend+"/"+name, func(t *testing.T) { run(t, mk) })
		}
	}
}

func TestServerBackends_ExistingAndEmptyDatabases(t *testing.T) {
	for backend, mk := range backends(t) {
		if backend == "sqlite" {
			continue
		}
		t.Run(backend, func(t *testing.T) {
			_, target, _ := mk(t)
			if !Exists(target) {
				t.Error("Exists should be true after Create")
			}
			if _, err := Create(target, vaultcrypto.Wrapped{}); err == nil {
				t.Error("creating a second vault in the same database must fail")
			}
			dropTables(t, target)
			if Exists(target) {
				t.Error("Exists should be false for an empty database")
			}
			if _, err := Open(target); err == nil || !strings.Contains(err.Error(), "no vault was found") {
				t.Errorf("opening an empty database: %v", err)
			}
		})
	}
}

func TestResolveTargets(t *testing.T) {
	cases := map[string]string{
		"/var/lib/otpmh/vault.db":                         "SQLite",
		"vault.db":                                        "SQLite",
		"postgres://u:p@db.example:5432/otp":              "PostgreSQL",
		"postgresql://u:p@db.example/otp?sslmode=require": "PostgreSQL",
		"mysql://u:p@db.example:3306/otp":                 "MySQL",
	}
	for target, want := range cases {
		d, _, err := resolve(target)
		if err != nil || d.name != want {
			t.Errorf("%s: got %q err %v, want %s", target, d.name, err, want)
		}
	}
	if _, _, err := resolve(""); err == nil {
		t.Error("empty target must fail")
	}
	if IsDatabaseURL("/var/lib/vault.db") || !IsDatabaseURL("mysql://u:p@h/db") || !IsDatabaseURL("postgres://u:p@h/db") {
		t.Error("IsDatabaseURL misclassifies")
	}
}

func TestMySQLDSN(t *testing.T) {
	dsn, err := mysqlDSN("mysql://otp:s3cret@db.example/vault?tls=skip-verify&timeout=5s")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"otp:s3cret@tcp(db.example:3306)/vault", "charset=utf8mb4", "tls=skip-verify", "timeout=5s"} {
		if !strings.Contains(dsn, want) {
			t.Errorf("dsn %q missing %q", dsn, want)
		}
	}
	for _, bad := range []string{"mysql://", "mysql://u:p@host", "mysql://u:p@/db"} {
		if _, err := mysqlDSN(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestDescribeNeverShowsThePassword(t *testing.T) {
	for _, target := range []string{"postgres://u:hunter2@db.example:5432/otp", "mysql://u:hunter2@db.example/otp"} {
		got := Describe(target)
		if strings.Contains(got, "hunter2") || !strings.Contains(got, "db.example") {
			t.Errorf("Describe(%q) = %q", target, got)
		}
	}
	if Describe("/data/vault.db") != "/data/vault.db" {
		t.Error("a file path should be shown as is")
	}
}

func TestRebindForPostgres(t *testing.T) {
	if got := postgresDialect.rebind("UPDATE t SET a = ?, b = ? WHERE id = ?"); got != "UPDATE t SET a = $1, b = $2 WHERE id = $3" {
		t.Errorf("got %q", got)
	}
	if got := sqliteDialect.rebind("a = ?"); got != "a = ?" {
		t.Errorf("sqlite should be untouched: %q", got)
	}
}
