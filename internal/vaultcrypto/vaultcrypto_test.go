package vaultcrypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"regexp"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestMain(m *testing.M) {
	workFactor = 10
	os.Exit(m.Run())
}

type sshKey struct {
	pub        string
	privatePEM []byte
}

func newSSHKey(t *testing.T, passphrase string) sshKey {
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
	return sshKey{pub: string(ssh.MarshalAuthorizedKey(sshPub)), privatePEM: pem.EncodeToMemory(block)}
}

func passphrase(p string) func() ([]byte, error) {
	return func() ([]byte, error) { return []byte(p), nil }
}

func newKey(t *testing.T) []byte {
	t.Helper()
	k, err := NewDataKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSealOpen_RoundTrip(t *testing.T) {
	key := newKey(t)
	sealed, err := Seal(key, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(key, sealed)
	if err != nil || string(got) != "secret" {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestOpen_TamperedFails(t *testing.T) {
	key := newKey(t)
	sealed, _ := Seal(key, []byte("secret"))
	sealed[len(sealed)-1] ^= 1
	if _, err := Open(key, sealed); err == nil {
		t.Error("expected error")
	}
}

func TestWrap_Password(t *testing.T) {
	key := newKey(t)
	w, err := Wrap(key, Setup{Mode: Password, Password: "hunter2"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unwrap(w, Unlock{Password: "hunter2"})
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("err %v", err)
	}
	if _, err := Unwrap(w, Unlock{Password: "wrong"}); err == nil || err.Error() != "unlock failed" {
		t.Errorf("wrong password err: %v", err)
	}
}

func TestWrap_SSH(t *testing.T) {
	k, other := newSSHKey(t, ""), newSSHKey(t, "")
	key := newKey(t)
	w, err := Wrap(key, Setup{Mode: SSH, SSHPublicKey: k.pub})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unwrap(w, Unlock{SSHPrivateKey: k.privatePEM})
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("err %v", err)
	}
	if _, err := Unwrap(w, Unlock{SSHPrivateKey: other.privatePEM}); err == nil || err.Error() != "unlock failed" {
		t.Errorf("wrong key err: %v", err)
	}
}

func TestWrap_SSHPassphrase(t *testing.T) {
	k := newSSHKey(t, "key-pass")
	key := newKey(t)
	w, err := Wrap(key, Setup{Mode: SSH, SSHPublicKey: k.pub})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unwrap(w, Unlock{SSHPrivateKey: k.privatePEM, SSHPassphrase: passphrase("key-pass")})
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("right passphrase: %v", err)
	}
	if _, err := Unwrap(w, Unlock{SSHPrivateKey: k.privatePEM, SSHPassphrase: passphrase("nope")}); err == nil {
		t.Error("wrong passphrase should fail")
	}
	if _, err := Unwrap(w, Unlock{SSHPrivateKey: k.privatePEM}); err == nil {
		t.Error("missing passphrase callback should fail")
	}
}

func TestWrap_Either(t *testing.T) {
	k := newSSHKey(t, "")
	key := newKey(t)
	w, err := Wrap(key, Setup{Mode: Either, Password: "pw", SSHPublicKey: k.pub})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Unwrap(w, Unlock{Password: "pw"}); err != nil || !bytes.Equal(got, key) {
		t.Errorf("password alone: %v", err)
	}
	if got, err := Unwrap(w, Unlock{SSHPrivateKey: k.privatePEM}); err != nil || !bytes.Equal(got, key) {
		t.Errorf("key alone: %v", err)
	}
}

func TestWrap_Both(t *testing.T) {
	k := newSSHKey(t, "")
	key := newKey(t)
	w, err := Wrap(key, Setup{Mode: Both, Password: "pw", SSHPublicKey: k.pub})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Unwrap(w, Unlock{Password: "pw", SSHPrivateKey: k.privatePEM}); err != nil || !bytes.Equal(got, key) {
		t.Errorf("both: %v", err)
	}
	if _, err := Unwrap(w, Unlock{Password: "pw"}); err == nil {
		t.Error("password alone should fail")
	}
	if _, err := Unwrap(w, Unlock{SSHPrivateKey: k.privatePEM}); err == nil {
		t.Error("key alone should fail")
	}
}

func TestWrap_CorruptBlob(t *testing.T) {
	key := newKey(t)
	w, _ := Wrap(key, Setup{Mode: Password, Password: "pw"})
	w.Password[len(w.Password)/2] ^= 0xff
	if _, err := Unwrap(w, Unlock{Password: "pw"}); err == nil || err.Error() != "unlock failed" {
		t.Errorf("err: %v", err)
	}
	if _, err := Unwrap(Wrapped{Mode: Password}, Unlock{Password: "pw"}); err == nil {
		t.Error("empty blob should fail")
	}
}

func TestRecovery_RoundTrip(t *testing.T) {
	key := newKey(t)
	var w Wrapped
	code, _ := NewRecoveryCode()
	if err := WrapRecovery(&w, key, code, "a-long-recovery-passphrase"); err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapRecovery(w, code, "a-long-recovery-passphrase")
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("err %v", err)
	}
}

func TestRecovery_RejectsShortPassphrase(t *testing.T) {
	var w Wrapped
	if err := WrapRecovery(&w, newKey(t), "CODE", "short"); err == nil {
		t.Error("expected error")
	}
}

func TestRecovery_WrongCodeOrPassphraseSameError(t *testing.T) {
	key := newKey(t)
	var w Wrapped
	code, _ := NewRecoveryCode()
	other, _ := NewRecoveryCode()
	pass := "a-long-recovery-passphrase"
	if err := WrapRecovery(&w, key, code, pass); err != nil {
		t.Fatal(err)
	}
	cases := [][2]string{{other, pass}, {code, "another-long-passphrase"}, {other, "another-long-passphrase"}}
	var first error
	for _, c := range cases {
		_, err := UnwrapRecovery(w, c[0], c[1])
		if err == nil || err.Error() != "recovery failed" {
			t.Fatalf("err: %v", err)
		}
		if first == nil {
			first = err
		} else if !errors.Is(err, first) && err.Error() != first.Error() {
			t.Error("errors differ")
		}
	}
	if _, err := UnwrapRecovery(Wrapped{}, code, pass); err == nil || err.Error() != "recovery failed" {
		t.Errorf("missing recovery data: %v", err)
	}
}

func TestRecoveryCode_Format(t *testing.T) {
	a, _ := NewRecoveryCode()
	b, _ := NewRecoveryCode()
	if !regexp.MustCompile(`^([A-Z2-7]{4}-){7}[A-Z2-7]{4}$`).MatchString(a) {
		t.Errorf("bad format %q", a)
	}
	if a == b {
		t.Error("codes should differ")
	}
}
