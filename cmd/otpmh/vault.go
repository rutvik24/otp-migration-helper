package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rutvik24/otp-migration-helper/internal/account"
	"github.com/rutvik24/otp-migration-helper/internal/migration"
	"github.com/rutvik24/otp-migration-helper/internal/prompt"
	"github.com/rutvik24/otp-migration-helper/internal/source"
	"github.com/rutvik24/otp-migration-helper/internal/store"
	"github.com/rutvik24/otp-migration-helper/internal/vault"
	"github.com/rutvik24/otp-migration-helper/internal/vaultcrypto"
)

const noRecoveryWarning = "Warning: without recovery, a lost password or key means the vault cannot be recovered."

func runVault(args []string, stdin io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: otpmh vault init|import|list|log|export|recover")
	}
	switch args[0] {
	case "init":
		return runVaultInit(args[1:], out)
	case "import":
		return runVaultImport(args[1:], stdin, out)
	case "list":
		return runVaultList(args[1:], out)
	case "export":
		return runVaultExport(args[1:], out)
	case "recover":
		return runVaultRecover(args[1:], out)
	case "log":
		return runVaultLog(args[1:], out)
	default:
		return fmt.Errorf("unknown vault command %q", args[0])
	}
}

// vaultFlags are shared by every vault command.
type vaultFlags struct {
	path        string
	databaseURL string
	identity    string
}

func addVaultFlags(fs *flag.FlagSet) *vaultFlags {
	f := &vaultFlags{}
	fs.StringVar(&f.path, "vault-path", "", "SQLite vault file (default: <user config dir>/otpmh/vault.db)")
	fs.StringVar(&f.databaseURL, "database-url", "", "keep the vault in PostgreSQL or MySQL (postgres://… or mysql://…); prefer OTPMH_DATABASE_URL so the password stays out of the process list")
	fs.StringVar(&f.identity, "ssh-identity", "", "SSH private key file used to unlock the vault")
	return f
}

// resolvePath returns the vault target: a SQLite file path or a database URL.
func (f *vaultFlags) resolvePath() (string, error) {
	return resolveTarget(f.databaseURL, f.path, os.Getenv)
}

// resolveTarget picks where the vault lives. Flags win over the environment:
// --database-url, then --vault-path, then OTPMH_DATABASE_URL, then a file named
// by OTPMH_DATABASE_URL_FILE (for Docker secrets), then OTPMH_VAULT_PATH, then
// the default file in the user's config directory.
func resolveTarget(databaseURL, path string, env func(string) string) (string, error) {
	switch {
	case databaseURL != "":
		return checkDatabaseURL(databaseURL)
	case path != "":
		return path, nil
	}
	if u := env("OTPMH_DATABASE_URL"); u != "" {
		return checkDatabaseURL(u)
	}
	if file := env("OTPMH_DATABASE_URL_FILE"); file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("OTPMH_DATABASE_URL_FILE: %w", err)
		}
		return checkDatabaseURL(strings.TrimSpace(string(data)))
	}
	if p := env("OTPMH_VAULT_PATH"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "otpmh", "vault.db"), nil
}

func checkDatabaseURL(u string) (string, error) {
	if !store.IsDatabaseURL(u) {
		return "", errors.New("the database URL must start with postgres://, postgresql:// or mysql://")
	}
	return u, nil
}

func runVaultInit(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("vault init", flag.ContinueOnError)
	fs.SetOutput(out)
	f := addVaultFlags(fs)
	unlock := fs.String("unlock", "", "password, ssh, either or both")
	sshKey := fs.String("ssh-key", "", "SSH public key file (.pub) that protects the vault")
	noRecovery := fs.Bool("no-recovery", false, "do not create recovery secrets")
	if err := fs.Parse(args); err != nil {
		return err
	}

	setup, err := collectSetup(*unlock, *sshKey)
	if err != nil {
		return err
	}

	recoveryPassphrase := ""
	if !*noRecovery {
		if recoveryPassphrase, err = askNew("Recovery passphrase (at least 12 characters)"); err != nil {
			return err
		}
	}

	path, err := f.resolvePath()
	if err != nil {
		return err
	}
	recoveryCode, err := vault.Create(path, vault.CreateOptions{Setup: setup, RecoveryPassphrase: recoveryPassphrase, NoRecovery: *noRecovery})
	if err != nil {
		return err
	}

	sayln(out, "Vault created:", store.Describe(path))
	if recoveryCode != "" {
		say(out, "Recovery code (shown once, store it safely): %s\n", recoveryCode)
		sayln(out, "Recovery also needs the recovery passphrase you just chose.")
	} else {
		sayln(out, noRecoveryWarning)
	}
	return nil
}

// collectSetup validates the unlock mode and asks for the new credentials it needs.
func collectSetup(unlock, sshKeyPath string) (vaultcrypto.Setup, error) {
	mode := vaultcrypto.Mode(unlock)
	needPassword := mode == vaultcrypto.Password || mode == vaultcrypto.Either || mode == vaultcrypto.Both
	needKey := mode == vaultcrypto.SSH || mode == vaultcrypto.Either || mode == vaultcrypto.Both
	if !needPassword && !needKey {
		return vaultcrypto.Setup{}, errors.New("--unlock must be password, ssh, either or both")
	}

	setup := vaultcrypto.Setup{Mode: mode}
	if needPassword {
		p, err := askNew("Password")
		if err != nil {
			return setup, err
		}
		setup.Password = p
	}
	if needKey {
		if sshKeyPath == "" {
			return setup, errors.New("--ssh-key (public key file) is required for this unlock mode")
		}
		pub, err := os.ReadFile(sshKeyPath)
		if err != nil {
			return setup, err
		}
		setup.SSHPublicKey = string(pub)
	}
	return setup, nil
}

func askNew(label string) (string, error) {
	first, err := prompt.Secret(label)
	if err != nil {
		return "", err
	}
	if first == "" {
		return "", errors.New("must not be empty")
	}
	second, err := prompt.Secret("Confirm " + strings.ToLower(label))
	if err != nil {
		return "", err
	}
	if first != second {
		return "", errors.New("entries do not match")
	}
	return first, nil
}

// openVault opens the vault and unlocks it, asking for what its mode needs.
func openVault(f *vaultFlags) (*store.Store, []byte, error) {
	path, err := f.resolvePath()
	if err != nil {
		return nil, nil, err
	}
	s, err := store.Open(path)
	if err != nil {
		return nil, nil, err
	}
	key, err := unlock(s, f.identity)
	if err != nil {
		_ = s.Close()
		return nil, nil, err
	}
	return s, key, nil
}

func unlock(s *store.Store, identity string) ([]byte, error) {
	w, err := s.Wrapped()
	if err != nil {
		return nil, err
	}
	usePassword, useKey := vault.Needs(w.Mode, identity != "")

	creds := vault.Creds{SSHIdentityPath: identity}
	if usePassword {
		if creds.Password, err = prompt.Secret("Password"); err != nil {
			return nil, err
		}
	}
	if useKey {
		if identity == "" {
			return nil, errors.New("this vault needs --ssh-identity (your SSH private key file)")
		}
		creds.SSHPassphrase = func() ([]byte, error) {
			p, err := prompt.Secret("SSH key passphrase")
			return []byte(p), err
		}
	}
	return vault.Unlock(s, creds)
}

func runVaultImport(args []string, stdin io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("vault import", flag.ContinueOnError)
	fs.SetOutput(out)
	f := addVaultFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	accounts, warnings, err := source.Load(fs.Args(), stdin)
	if err != nil {
		return err
	}
	for _, w := range warnings {
		sayln(out, "warning:", w)
	}

	s, key, err := openVault(f)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	added, err := s.AddAccounts(key, accounts)
	if err != nil {
		return err
	}
	if err := s.Log("import", fmt.Sprintf("added=%d", added)); err != nil {
		return err
	}
	say(out, "added %d of %d accounts\n", added, len(accounts))
	return nil
}

func runVaultList(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("vault list", flag.ContinueOnError)
	fs.SetOutput(out)
	f := addVaultFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, key, err := openVault(f)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	recs, err := s.Accounts(key)
	if err != nil {
		return err
	}
	for _, r := range recs {
		if _, err := fmt.Fprintf(out, "%d  %s\n", r.ID, account.Label(r.Account)); err != nil {
			return err
		}
	}
	return nil
}

// runVaultLog shows the activity log. It holds no secrets, so it needs no unlock.
func runVaultLog(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("vault log", flag.ContinueOnError)
	fs.SetOutput(out)
	f := addVaultFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	path, err := f.resolvePath()
	if err != nil {
		return err
	}
	s, err := store.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	logs, err := s.Logs()
	if err != nil {
		return err
	}
	for _, e := range logs {
		if _, err := fmt.Fprintf(out, "%s  %s  %s\n", e.Time.Format("2006-01-02 15:04:05"), e.Action, e.Detail); err != nil {
			return err
		}
	}
	return nil
}

// vaultAccounts unlocks the vault and returns it with its accounts. The caller closes the store.
func vaultAccounts(f *vaultFlags) (*store.Store, []store.Record, error) {
	s, key, err := openVault(f)
	if err != nil {
		return nil, nil, err
	}
	recs, err := s.Accounts(key)
	if err != nil {
		_ = s.Close()
		return nil, nil, err
	}
	return s, recs, nil
}

func accountsOf(recs []store.Record) []migration.Account {
	accounts := make([]migration.Account, len(recs))
	for i, r := range recs {
		accounts[i] = r.Account
	}
	return accounts
}

// matching returns the records for the chosen accounts, in the chosen order.
func matching(recs []store.Record, chosen []migration.Account) []store.Record {
	var out []store.Record
	for _, c := range chosen {
		for _, r := range recs {
			if r.Issuer == c.Issuer && r.Name == c.Name && bytes.Equal(r.Secret, c.Secret) {
				out = append(out, r)
				break
			}
		}
	}
	return out
}

// counterSaver returns a live-view callback that saves HOTP counters; index
// refers to the position in recs.
func counterSaver(s *store.Store, recs []store.Record) func(int, uint64) error {
	return func(index int, counter uint64) error {
		return s.SetCounter(recs[index].ID, counter)
	}
}

func runVaultExport(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("vault export", flag.ContinueOnError)
	fs.SetOutput(out)
	f := addVaultFlags(fs)
	format := fs.String("format", "", "bitwarden, passwords-csv, otpauth, aegis or andotp (for Google Authenticator QR codes use otpmh qr)")
	yes := fs.Bool("yes", false, "confirm writing unencrypted secrets")
	outFile := fs.String("out", "", "write to this new file instead of the terminal")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*yes {
		return errors.New("export is unencrypted: pass --yes to confirm")
	}

	s, recs, err := vaultAccounts(f)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	accounts := accountsOf(recs)

	data, err := vault.Export(*format, accounts)
	if err != nil {
		return err
	}

	if err := writeExport(*outFile, data, out); err != nil {
		return err
	}
	if err := s.Log("export", fmt.Sprintf("format=%s accounts=%d", *format, len(accounts))); err != nil {
		return err
	}
	if *outFile != "" {
		say(out, "Wrote %d accounts to %s. The file is unencrypted: delete it after importing.\n", len(accounts), *outFile)
	}
	return nil
}

// writeExport writes to a new owner-only file, or to out when path is empty.
func writeExport(path string, data []byte, out io.Writer) error {
	if path == "" {
		_, err := out.Write(data)
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// runVaultRecover opens the vault with the recovery code and passphrase and
// replaces the unlock credentials and recovery secrets. Every failure,
// including being locked out, returns the same error.
func runVaultRecover(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("vault recover", flag.ContinueOnError)
	fs.SetOutput(out)
	f := addVaultFlags(fs)
	unlock := fs.String("unlock", "", "new unlock mode: password, ssh, either or both")
	sshKey := fs.String("ssh-key", "", "new SSH public key file (.pub)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	path, err := f.resolvePath()
	if err != nil {
		return err
	}
	code, err := prompt.Secret("Recovery code")
	if err != nil {
		return err
	}
	pass, err := prompt.Secret("Recovery passphrase")
	if err != nil {
		return err
	}

	newCode, err := vault.Recover(path, code, pass, func() (vault.NewCredentials, error) {
		setup, err := collectSetup(*unlock, *sshKey)
		if err != nil {
			return vault.NewCredentials{}, err
		}
		recoveryPassphrase, err := askNew("Recovery passphrase (at least 12 characters)")
		return vault.NewCredentials{Setup: setup, RecoveryPassphrase: recoveryPassphrase}, err
	})
	if err != nil {
		return err
	}
	sayln(out, "Vault recovered. Your old recovery code no longer works.")
	say(out, "New recovery code (shown once, store it safely): %s\n", newCode)
	return nil
}
