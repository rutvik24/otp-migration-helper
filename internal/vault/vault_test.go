package vault

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/rutvik24/otp-migration-helper/internal/migration"
	"github.com/rutvik24/otp-migration-helper/internal/otp"
	"github.com/rutvik24/otp-migration-helper/internal/store"
	"github.com/rutvik24/otp-migration-helper/internal/vaultcrypto"
)

func TestMain(m *testing.M) {
	vaultcrypto.SetWorkFactorForTests(10)
	os.Exit(m.Run())
}

const (
	pw      = "correct horse"
	recPass = "recovery-passphrase-1"
)

func vaultPath(t *testing.T) string { return filepath.Join(t.TempDir(), "sub", "vault.db") }

func account(name string) migration.Account {
	return migration.Account{Name: name, Issuer: "Acme", Secret: []byte("12345678901234567890"), Digits: 6, Algorithm: otp.SHA1, Kind: migration.TOTP}
}

type keyFiles struct{ pub, identity string }

func newKeyFiles(t *testing.T, passphrase string) keyFiles {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(priv, "")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	k := keyFiles{pub: filepath.Join(dir, "id.pub"), identity: filepath.Join(dir, "id")}
	if err := os.WriteFile(k.pub, ssh.MarshalAuthorizedKey(sshPub), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(k.identity, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return k
}

func createPassword(t *testing.T, path string) string {
	t.Helper()
	code, err := Create(path, CreateOptions{Setup: vaultcrypto.Setup{Mode: vaultcrypto.Password, Password: pw}, RecoveryPassphrase: recPass})
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func TestCreateOpenPassword(t *testing.T) {
	path := vaultPath(t)
	code := createPassword(t, path)
	if code == "" || !Exists(path) {
		t.Fatalf("code=%q exists=%v", code, Exists(path))
	}
	if mode, err := ModeOf(path); err != nil || mode != vaultcrypto.Password {
		t.Errorf("mode=%v err=%v", mode, err)
	}
	s, err := Open(path, Creds{Password: pw})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if n, err := s.Import([]migration.Account{account("a")}); err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	recs, err := s.Records()
	if err != nil || len(recs) != 1 || recs[0].Name != "a" {
		t.Errorf("recs=%+v err=%v", recs, err)
	}
}

func TestOpenWrongPasswordGeneric(t *testing.T) {
	path := vaultPath(t)
	createPassword(t, path)
	if _, err := Open(path, Creds{Password: "wrong"}); err == nil || err.Error() != "unlock failed" {
		t.Errorf("err: %v", err)
	}
}

func TestCreateModes(t *testing.T) {
	plain := newKeyFiles(t, "")
	locked := newKeyFiles(t, "key-pass")
	pass := func() ([]byte, error) { return []byte("key-pass"), nil }
	cases := []struct {
		name  string
		setup func(keyFiles) vaultcrypto.Setup
		key   keyFiles
		creds Creds
	}{
		{"ssh", func(k keyFiles) vaultcrypto.Setup {
			return vaultcrypto.Setup{Mode: vaultcrypto.SSH, SSHPublicKey: readFile(t, k.pub)}
		}, plain, Creds{SSHIdentityPath: plain.identity}},
		{"ssh with passphrase", func(k keyFiles) vaultcrypto.Setup {
			return vaultcrypto.Setup{Mode: vaultcrypto.SSH, SSHPublicKey: readFile(t, k.pub)}
		}, locked, Creds{SSHIdentityPath: locked.identity, SSHPassphrase: pass}},
		{"either by key", func(k keyFiles) vaultcrypto.Setup {
			return vaultcrypto.Setup{Mode: vaultcrypto.Either, Password: pw, SSHPublicKey: readFile(t, k.pub)}
		}, plain, Creds{SSHIdentityPath: plain.identity}},
		{"either by password", func(k keyFiles) vaultcrypto.Setup {
			return vaultcrypto.Setup{Mode: vaultcrypto.Either, Password: pw, SSHPublicKey: readFile(t, k.pub)}
		}, plain, Creds{Password: pw}},
		{"both", func(k keyFiles) vaultcrypto.Setup {
			return vaultcrypto.Setup{Mode: vaultcrypto.Both, Password: pw, SSHPublicKey: readFile(t, k.pub)}
		}, plain, Creds{Password: pw, SSHIdentityPath: plain.identity}},
	}
	for _, c := range cases {
		path := vaultPath(t)
		if _, err := Create(path, CreateOptions{Setup: c.setup(c.key), NoRecovery: true}); err != nil {
			t.Fatalf("%s: create: %v", c.name, err)
		}
		s, err := Open(path, c.creds)
		if err != nil {
			t.Errorf("%s: open: %v", c.name, err)
			continue
		}
		_ = s.Close()
	}

	path := vaultPath(t)
	if _, err := Create(path, CreateOptions{Setup: vaultcrypto.Setup{Mode: vaultcrypto.Both, Password: pw, SSHPublicKey: readFile(t, plain.pub)}, NoRecovery: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, Creds{Password: pw}); err == nil {
		t.Error("both mode opened with the password alone")
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestImportExportRoundTrip(t *testing.T) {
	path := vaultPath(t)
	createPassword(t, path)
	s, err := Open(path, Creds{Password: pw})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if _, err := s.Import([]migration.Account{account("a"), account("b")}); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"bitwarden", "passwords-csv", "otpauth"} {
		data, err := s.Export(format)
		if err != nil || !strings.Contains(string(data), "otpauth://totp/Acme:a") {
			t.Errorf("%s: err=%v data=%q", format, err, data)
		}
	}
	if _, err := s.Export("nope"); err == nil {
		t.Error("unknown format should fail")
	}
}

func TestRecoverRotatesAndLocksOut(t *testing.T) {
	path := vaultPath(t)
	code := createPassword(t, path)
	s, _ := Open(path, Creds{Password: pw})
	if _, err := s.Import([]migration.Account{account("a")}); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	next := func() (NewCredentials, error) {
		return NewCredentials{Setup: vaultcrypto.Setup{Mode: vaultcrypto.Password, Password: "new password"}, RecoveryPassphrase: "new-recovery-pass-2"}, nil
	}
	newCode, err := Recover(path, code, recPass, next)
	if err != nil || newCode == "" || newCode == code {
		t.Fatalf("newCode=%q err=%v", newCode, err)
	}
	if _, err := Open(path, Creds{Password: pw}); err == nil {
		t.Error("old password still works")
	}
	s, err = Open(path, Creds{Password: "new password"})
	if err != nil {
		t.Fatal(err)
	}
	if recs, err := s.Records(); err != nil || len(recs) != 1 {
		t.Errorf("recs=%v err=%v", recs, err)
	}
	_ = s.Close()

	for i := 0; i < 5; i++ {
		if _, err := Recover(path, "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA", recPass, next); err == nil || err.Error() != "recovery failed" {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if _, err := Recover(path, newCode, "new-recovery-pass-2", next); err == nil || err.Error() != "recovery failed" {
		t.Errorf("correct secrets accepted while locked: %v", err)
	}
}

func TestLogsNeverContainSecrets(t *testing.T) {
	path := vaultPath(t)
	code := createPassword(t, path)
	_, _ = Open(path, Creds{Password: "wrong"})
	s, _ := Open(path, Creds{Password: pw})
	if _, err := s.Import([]migration.Account{account("a")}); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	logs, err := Logs(path)
	if err != nil {
		t.Fatal(err)
	}
	var all strings.Builder
	for _, e := range logs {
		all.WriteString(e.Action + " " + e.Detail + "\n")
	}
	for _, secret := range []string{pw, recPass, code, "12345678901234567890", "GEZDGNBVGY3TQOJQ"} {
		if strings.Contains(all.String(), secret) {
			t.Errorf("log leaks %q", secret)
		}
	}
	for _, action := range []string{"create", "unlock", "unlock_failed", "import"} {
		if !strings.Contains(all.String(), action) {
			t.Errorf("log missing %q", action)
		}
	}
}

func TestOpenWithKeyText(t *testing.T) {
	k := newKeyFiles(t, "key-pass")
	path := vaultPath(t)
	if _, err := Create(path, CreateOptions{Setup: vaultcrypto.Setup{Mode: vaultcrypto.SSH, SSHPublicKey: readFile(t, k.pub)}, NoRecovery: true}); err != nil {
		t.Fatal(err)
	}
	pass := func() ([]byte, error) { return []byte("key-pass"), nil }
	s, err := Open(path, Creds{SSHPrivateKey: []byte(readFile(t, k.identity)), SSHPassphrase: pass})
	if err != nil {
		t.Fatalf("pasted key text should unlock: %v", err)
	}
	_ = s.Close()
	if _, err := Open(path, Creds{SSHPrivateKey: []byte(readFile(t, k.identity))}); err == nil {
		t.Error("a passphrase-protected key without its passphrase must fail")
	}
	if _, err := Open(path, Creds{}); err == nil {
		t.Error("no key at all must fail")
	}
}

func TestVerify(t *testing.T) {
	k := newKeyFiles(t, "")
	path := vaultPath(t)
	if _, err := Create(path, CreateOptions{Setup: vaultcrypto.Setup{Mode: vaultcrypto.Both, Password: pw, SSHPublicKey: readFile(t, k.pub)}, NoRecovery: true}); err != nil {
		t.Fatal(err)
	}
	key := []byte(readFile(t, k.identity))
	if err := Verify(path, Creds{Password: pw, SSHPrivateKey: key}); err != nil {
		t.Errorf("right credentials: %v", err)
	}
	for name, c := range map[string]Creds{
		"password only": {Password: pw},
		"key only":      {SSHPrivateKey: key},
		"wrong":         {Password: "nope", SSHPrivateKey: key},
	} {
		if err := Verify(path, c); err == nil || err.Error() != "unlock failed" {
			t.Errorf("%s: %v", name, err)
		}
	}
	logs, err := Logs(path)
	if err != nil {
		t.Fatal(err)
	}
	var verify, failed int
	for _, e := range logs {
		switch e.Action {
		case "verify":
			verify++
		case "verify_failed":
			failed++
		case "unlock", "unlock_failed":
			t.Errorf("verification must not be logged as %s", e.Action)
		}
	}
	if verify != 1 || failed != 3 {
		t.Errorf("verify=%d failed=%d", verify, failed)
	}
}

// The same lifecycle on real PostgreSQL / MySQL servers, when their test URLs are set.
func TestLifecycle_OnServerDatabases(t *testing.T) {
	for name, envName := range map[string]string{"postgres": "OTPMH_TEST_POSTGRES_URL", "mysql": "OTPMH_TEST_MYSQL_URL"} {
		target := os.Getenv(envName)
		if target == "" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			if err := store.DropForTests(target); err != nil {
				t.Fatal(err)
			}
			if Exists(target) {
				t.Fatal("database should start empty")
			}
			code, err := Create(target, CreateOptions{Setup: vaultcrypto.Setup{Mode: vaultcrypto.Password, Password: pw}, RecoveryPassphrase: recPass})
			if err != nil || code == "" || !Exists(target) {
				t.Fatalf("create: code=%q err=%v", code, err)
			}
			s, err := Open(target, Creds{Password: pw})
			if err != nil {
				t.Fatal(err)
			}
			if n, err := s.Import([]migration.Account{account("a"), account("b")}); err != nil || n != 2 {
				t.Fatalf("import n=%d err=%v", n, err)
			}
			if n, _ := s.Import([]migration.Account{account("a")}); n != 0 {
				t.Errorf("duplicate import added %d", n)
			}
			if data, err := s.Export("otpauth"); err != nil || !strings.Contains(string(data), "Acme:a") {
				t.Errorf("export: %v %q", err, data)
			}
			_ = s.Close()
			if err := Verify(target, Creds{Password: pw}); err != nil {
				t.Errorf("verify: %v", err)
			}
			if _, err := Open(target, Creds{Password: "wrong"}); err == nil {
				t.Error("wrong password opened the vault")
			}
			next := func() (NewCredentials, error) {
				return NewCredentials{Setup: vaultcrypto.Setup{Mode: vaultcrypto.Password, Password: "new password"}, RecoveryPassphrase: "new-recovery-pass-2"}, nil
			}
			if _, err := Recover(target, code, recPass, next); err != nil {
				t.Fatalf("recover: %v", err)
			}
			s, err = Open(target, Creds{Password: "new password"})
			if err != nil {
				t.Fatal(err)
			}
			if recs, err := s.Records(); err != nil || len(recs) != 2 {
				t.Errorf("accounts after rekey: %v %v", recs, err)
			}
			_ = s.Close()
			if logs, err := Logs(target); err != nil || len(logs) < 5 {
				t.Errorf("logs: %d %v", len(logs), err)
			}
		})
	}
}

func TestExport_OtherAppFormats(t *testing.T) {
	path := vaultPath(t)
	createPassword(t, path)
	s, err := Open(path, Creds{Password: pw})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if _, err := s.Import([]migration.Account{account("a")}); err != nil {
		t.Fatal(err)
	}
	for format, want := range map[string]string{"aegis": `"issuer": "Acme"`, "andotp": `"label": "a"`} {
		data, err := s.Export(format)
		if err != nil || !strings.Contains(string(data), want) || !strings.Contains(string(data), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ") {
			t.Errorf("%s: err=%v\n%s", format, err, data)
		}
	}
}
