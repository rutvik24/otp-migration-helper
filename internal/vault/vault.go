// Package vault holds the vault operations shared by the command line and the
// web interface. Everything takes explicit credentials; nothing prompts.
package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rutvik24/otp-migration-helper/internal/export"
	"github.com/rutvik24/otp-migration-helper/internal/migration"
	"github.com/rutvik24/otp-migration-helper/internal/store"
	"github.com/rutvik24/otp-migration-helper/internal/vaultcrypto"
)

// ErrRecoveryFailed is the only error recovery ever reports.
var ErrRecoveryFailed = errors.New("recovery failed")

// Creds are the credentials offered when unlocking. The SSH key is given as
// text (SSHPrivateKey, for example uploaded in the browser) or as the path of a
// key file on this machine (SSHIdentityPath); the text wins when both are set.
type Creds struct {
	Password        string
	SSHPrivateKey   []byte
	SSHIdentityPath string
	SSHPassphrase   func() ([]byte, error)
}

func (c Creds) hasKey() bool { return len(c.SSHPrivateKey) > 0 || c.SSHIdentityPath != "" }

type CreateOptions struct {
	Setup              vaultcrypto.Setup
	RecoveryPassphrase string
	NoRecovery         bool
}

// NewCredentials replace the old ones after a successful recovery.
type NewCredentials struct {
	Setup              vaultcrypto.Setup
	RecoveryPassphrase string
}

// Exists reports whether a vault has been created at the target: a SQLite file
// path, or a postgres:// or mysql:// URL.
func Exists(target string) bool { return store.Exists(target) }

func ModeOf(path string) (vaultcrypto.Mode, error) {
	s, err := store.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = s.Close() }()
	w, err := s.Wrapped()
	return w.Mode, err
}

// Needs reports which credentials unlocking asks for. In either mode the SSH
// key is used when an identity file is given, otherwise the password.
func Needs(mode vaultcrypto.Mode, identityGiven bool) (password, key bool) {
	key = mode == vaultcrypto.SSH || mode == vaultcrypto.Both || (mode == vaultcrypto.Either && identityGiven)
	password = mode == vaultcrypto.Password || mode == vaultcrypto.Both || (mode == vaultcrypto.Either && !identityGiven)
	return password, key
}

// Create makes a new vault and returns its recovery code (empty with NoRecovery).
func Create(path string, o CreateOptions) (string, error) {
	dataKey, err := vaultcrypto.NewDataKey()
	if err != nil {
		return "", err
	}
	wrapped, err := vaultcrypto.Wrap(dataKey, o.Setup)
	if err != nil {
		return "", err
	}
	code := ""
	if !o.NoRecovery {
		if code, err = vaultcrypto.NewRecoveryCode(); err != nil {
			return "", err
		}
		if err := vaultcrypto.WrapRecovery(&wrapped, dataKey, code, o.RecoveryPassphrase); err != nil {
			return "", err
		}
	}

	if !store.IsDatabaseURL(path) {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return "", err
		}
	}
	s, err := store.Create(path, wrapped)
	if err != nil {
		return "", err
	}
	defer func() { _ = s.Close() }()
	return code, s.Log("create", "mode="+string(o.Setup.Mode))
}

// Unlock returns the data key and logs the outcome. Every failure to open the
// vault with the given credentials returns the same error.
func Unlock(s *store.Store, c Creds) ([]byte, error) {
	return unlock(s, c, "unlock", "unlock_failed")
}

func unlock(s *store.Store, c Creds, okAction, failAction string) ([]byte, error) {
	w, err := s.Wrapped()
	if err != nil {
		return nil, err
	}
	_, useKey := Needs(w.Mode, c.hasKey())

	u := vaultcrypto.Unlock{Password: c.Password, SSHPassphrase: c.SSHPassphrase}
	if useKey {
		switch {
		case len(c.SSHPrivateKey) > 0:
			u.SSHPrivateKey = c.SSHPrivateKey
		case c.SSHIdentityPath != "":
			if u.SSHPrivateKey, err = os.ReadFile(c.SSHIdentityPath); err != nil {
				return nil, err
			}
		}
		// With no key at all, Unwrap fails like any wrong credential, so a
		// missing key is logged and counted the same way.
	}

	key, err := vaultcrypto.Unwrap(w, u)
	if err != nil {
		if logErr := s.Log(failAction, ""); logErr != nil {
			return nil, logErr
		}
		return nil, err
	}
	return key, s.Log(okAction, "")
}

// Verify checks that the credentials open the vault without starting a
// session, for confirming the user before a sensitive action. It is logged as
// verify / verify_failed.
func Verify(path string, c Creds) error {
	s, err := store.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	key, err := unlock(s, c, "verify", "verify_failed")
	for i := range key {
		key[i] = 0
	}
	return err
}

// Session is an unlocked vault.
type Session struct {
	store *store.Store
	key   []byte
}

func Open(path string, c Creds) (*Session, error) {
	s, err := store.Open(path)
	if err != nil {
		return nil, err
	}
	key, err := Unlock(s, c)
	if err != nil {
		_ = s.Close()
		return nil, err
	}
	return &Session{store: s, key: key}, nil
}

// Close forgets the data key and closes the vault file.
func (s *Session) Close() error {
	for i := range s.key {
		s.key[i] = 0
	}
	return s.store.Close()
}

func (s *Session) Records() ([]store.Record, error) { return s.store.Accounts(s.key) }

func (s *Session) Import(accts []migration.Account) (int, error) {
	added, err := s.store.AddAccounts(s.key, accts)
	if err != nil {
		return 0, err
	}
	return added, s.store.Log("import", fmt.Sprintf("added=%d", added))
}

func (s *Session) SetCounter(id int64, counter uint64) error { return s.store.SetCounter(id, counter) }

func (s *Session) Log(action, detail string) error { return s.store.Log(action, detail) }

func (s *Session) Logs() ([]store.LogEntry, error) { return s.store.Logs() }

// Export returns every account in the given format (unencrypted) and logs it.
func (s *Session) Export(format string) ([]byte, error) {
	recs, err := s.Records()
	if err != nil {
		return nil, err
	}
	accounts := make([]migration.Account, len(recs))
	for i, r := range recs {
		accounts[i] = r.Account
	}
	data, err := Export(format, accounts)
	if err != nil {
		return nil, err
	}
	return data, s.store.Log("export", fmt.Sprintf("format=%s accounts=%d", format, len(accounts)))
}

// Export formats accounts for a password manager: bitwarden, passwords-csv or otpauth.
func Export(format string, accounts []migration.Account) ([]byte, error) {
	switch format {
	case "bitwarden":
		return export.Bitwarden(accounts)
	case "passwords-csv":
		return export.PasswordsCSV(accounts)
	case "otpauth":
		return export.OTPAuthList(accounts), nil
	}
	return nil, errors.New("format must be bitwarden, passwords-csv or otpauth")
}

// Logs returns the activity log; it holds no secrets, so it needs no unlock.
func Logs(path string) ([]store.LogEntry, error) {
	s, err := store.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = s.Close() }()
	return s.Logs()
}

// Recover opens the vault with the recovery code and passphrase, then asks
// next for the new credentials (only after the recovery secrets are proven),
// rotates the data key and issues a new recovery code. Every failure, including
// a lockout, returns ErrRecoveryFailed.
func Recover(path, code, passphrase string, next func() (NewCredentials, error)) (string, error) {
	s, err := store.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = s.Close() }()

	_, lockedUntil, err := s.RecoveryState()
	if err != nil {
		return "", err
	}
	if time.Now().Before(lockedUntil) {
		if err := s.Log("recovery_blocked", ""); err != nil {
			return "", err
		}
		return "", ErrRecoveryFailed
	}

	wrapped, err := s.Wrapped()
	if err != nil {
		return "", err
	}
	oldKey, err := vaultcrypto.UnwrapRecovery(wrapped, code, passphrase)
	if err != nil {
		if err := s.RecordRecoveryFailure(time.Now()); err != nil {
			return "", err
		}
		if err := s.Log("recovery_failed", ""); err != nil {
			return "", err
		}
		return "", ErrRecoveryFailed
	}

	creds, err := next()
	if err != nil {
		return "", err
	}
	// A fresh data key means nothing sealed under the old one stays readable.
	newKey, err := vaultcrypto.NewDataKey()
	if err != nil {
		return "", err
	}
	rewrapped, err := vaultcrypto.Wrap(newKey, creds.Setup)
	if err != nil {
		return "", err
	}
	newCode, err := vaultcrypto.NewRecoveryCode()
	if err != nil {
		return "", err
	}
	if err := vaultcrypto.WrapRecovery(&rewrapped, newKey, newCode, creds.RecoveryPassphrase); err != nil {
		return "", err
	}
	if err := s.Rekey(oldKey, newKey, rewrapped); err != nil {
		return "", err
	}
	if err := s.ClearRecoveryFailures(); err != nil {
		return "", err
	}
	return newCode, s.Log("recovery", "mode="+string(creds.Setup.Mode))
}
