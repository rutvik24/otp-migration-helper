// Package vaultcrypto protects the vault's data key with passwords, SSH keys
// and recovery secrets (all via age) and encrypts rows with XChaCha20-Poly1305.
package vaultcrypto

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/ssh"
)

type Mode string

const (
	Password Mode = "password"
	SSH      Mode = "ssh"
	Either   Mode = "either"
	Both     Mode = "both"
)

const minRecoveryPassphrase = 12

var (
	errUnlock   = errors.New("unlock failed")
	errRecovery = errors.New("recovery failed")
)

// workFactor is the age scrypt cost (log2 N); tests lower it.
var workFactor = 18

// Wrapped holds the data key encrypted for each unlock method.
type Wrapped struct {
	Mode     Mode
	Password []byte
	SSH      []byte
	Both     []byte
	Recovery []byte
}

// Setup is what is needed to protect a data key: only the SSH public key.
type Setup struct {
	Mode         Mode
	Password     string
	SSHPublicKey string
}

// Unlock is what is needed to open it: the SSH private key (and its
// passphrase, if the key has one).
type Unlock struct {
	Password      string
	SSHPrivateKey []byte
	SSHPassphrase func() ([]byte, error)
}

func NewDataKey() ([]byte, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	_, err := rand.Read(key)
	return key, err
}

func Seal(dataKey, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(dataKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

func Open(dataKey, sealed []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(dataKey)
	if err != nil {
		return nil, err
	}
	if len(sealed) < aead.NonceSize() {
		return nil, errors.New("sealed data too short")
	}
	nonce, ciphertext := sealed[:aead.NonceSize()], sealed[aead.NonceSize():]
	return aead.Open(nil, nonce, ciphertext, nil)
}

func Wrap(dataKey []byte, s Setup) (Wrapped, error) {
	w := Wrapped{Mode: s.Mode}
	var err error
	switch s.Mode {
	case Password:
		w.Password, err = scryptEncrypt(dataKey, s.Password)
	case SSH:
		w.SSH, err = sshEncrypt(dataKey, s.SSHPublicKey)
	case Either:
		if w.Password, err = scryptEncrypt(dataKey, s.Password); err == nil {
			w.SSH, err = sshEncrypt(dataKey, s.SSHPublicKey)
		}
	case Both:
		var inner []byte
		if inner, err = sshEncrypt(dataKey, s.SSHPublicKey); err == nil {
			w.Both, err = scryptEncrypt(inner, s.Password)
		}
	default:
		err = fmt.Errorf("unknown unlock mode %q", s.Mode)
	}
	return w, err
}

// Unwrap returns the data key. Every failure returns the same error.
func Unwrap(w Wrapped, u Unlock) ([]byte, error) {
	key, err := unwrap(w, u)
	if err != nil {
		return nil, errUnlock
	}
	return key, nil
}

func unwrap(w Wrapped, u Unlock) ([]byte, error) {
	switch w.Mode {
	case Password:
		return scryptDecrypt(w.Password, u.Password)
	case SSH:
		return sshDecrypt(w.SSH, u)
	case Either:
		if u.Password != "" {
			if key, err := scryptDecrypt(w.Password, u.Password); err == nil {
				return key, nil
			}
		}
		return sshDecrypt(w.SSH, u)
	case Both:
		inner, err := scryptDecrypt(w.Both, u.Password)
		if err != nil {
			return nil, err
		}
		return sshDecrypt(inner, u)
	}
	return nil, errUnlock
}

// NewRecoveryCode returns 160 random bits as groups of four base32 characters.
func NewRecoveryCode() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	enc := base32.StdEncoding.EncodeToString(raw)
	groups := make([]string, 0, len(enc)/4)
	for i := 0; i < len(enc); i += 4 {
		groups = append(groups, enc[i:i+4])
	}
	return strings.Join(groups, "-"), nil
}

// WrapRecovery needs both the recovery code and the recovery passphrase to open.
func WrapRecovery(w *Wrapped, dataKey []byte, code, passphrase string) error {
	if len(passphrase) < minRecoveryPassphrase {
		return fmt.Errorf("recovery passphrase must be at least %d characters", minRecoveryPassphrase)
	}
	inner, err := scryptEncrypt(dataKey, normalizeCode(code))
	if err != nil {
		return err
	}
	w.Recovery, err = scryptEncrypt(inner, passphrase)
	return err
}

// UnwrapRecovery returns the data key; every failure returns the same error.
func UnwrapRecovery(w Wrapped, code, passphrase string) ([]byte, error) {
	inner, err := scryptDecrypt(w.Recovery, passphrase)
	if err != nil {
		return nil, errRecovery
	}
	key, err := scryptDecrypt(inner, normalizeCode(code))
	if err != nil {
		return nil, errRecovery
	}
	return key, nil
}

func normalizeCode(code string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(code))
}

func scryptEncrypt(plain []byte, password string) ([]byte, error) {
	r, err := age.NewScryptRecipient(password)
	if err != nil {
		return nil, err
	}
	r.SetWorkFactor(workFactor)
	return ageEncrypt(plain, r)
}

func scryptDecrypt(blob []byte, password string) ([]byte, error) {
	id, err := age.NewScryptIdentity(password)
	if err != nil {
		return nil, err
	}
	return ageDecrypt(blob, id)
}

func sshEncrypt(plain []byte, publicKey string) ([]byte, error) {
	r, err := agessh.ParseRecipient(strings.TrimSpace(publicKey))
	if err != nil {
		return nil, err
	}
	return ageEncrypt(plain, r)
}

func sshDecrypt(blob []byte, u Unlock) ([]byte, error) {
	id, err := agessh.ParseIdentity(u.SSHPrivateKey)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		if u.SSHPassphrase == nil {
			return nil, errors.New("key needs a passphrase")
		}
		id, err = agessh.NewEncryptedSSHIdentity(missing.PublicKey, u.SSHPrivateKey, u.SSHPassphrase)
	}
	if err != nil {
		return nil, err
	}
	return ageDecrypt(blob, id)
}

func ageEncrypt(plain []byte, r age.Recipient) ([]byte, error) {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plain); err != nil {
		_ = w.Close()
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func ageDecrypt(blob []byte, id age.Identity) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(blob), id)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// SetWorkFactorForTests lowers the scrypt cost so tests that create many
// vaults stay fast. Never call it outside tests.
func SetWorkFactorForTests(logN int) { workFactor = logN }
