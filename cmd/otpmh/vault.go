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
	case "log":
		return runVaultLog(args[1:], out)
	default:
		return fmt.Errorf("unknown vault command %q", args[0])
	}
}

// vaultFlags are shared by every vault command.
type vaultFlags struct {
	path     string
	identity string
}

func addVaultFlags(fs *flag.FlagSet) *vaultFlags {
	f := &vaultFlags{}
	fs.StringVar(&f.path, "vault-path", "", "vault file (default: <user config dir>/otpmh/vault.db)")
	fs.StringVar(&f.identity, "ssh-identity", "", "SSH private key file used to unlock the vault")
	return f
}

func (f *vaultFlags) resolvePath() (string, error) {
	if f.path != "" {
		return f.path, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "otpmh", "vault.db"), nil
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

	mode := vaultcrypto.Mode(*unlock)
	needPassword := mode == vaultcrypto.Password || mode == vaultcrypto.Either || mode == vaultcrypto.Both
	needKey := mode == vaultcrypto.SSH || mode == vaultcrypto.Either || mode == vaultcrypto.Both
	if !needPassword && !needKey {
		return errors.New("--unlock must be password, ssh, either or both")
	}

	setup := vaultcrypto.Setup{Mode: mode}
	if needPassword {
		p, err := askNew("Password")
		if err != nil {
			return err
		}
		setup.Password = p
	}
	if needKey {
		if *sshKey == "" {
			return errors.New("--ssh-key (public key file) is required for this unlock mode")
		}
		pub, err := os.ReadFile(*sshKey)
		if err != nil {
			return err
		}
		setup.SSHPublicKey = string(pub)
	}

	dataKey, err := vaultcrypto.NewDataKey()
	if err != nil {
		return err
	}
	wrapped, err := vaultcrypto.Wrap(dataKey, setup)
	if err != nil {
		return err
	}
	recoveryCode := ""
	if !*noRecovery {
		if recoveryCode, err = addRecovery(&wrapped, dataKey); err != nil {
			return err
		}
	}

	path, err := f.resolvePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	s, err := store.Create(path, wrapped)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	if err := s.Log("create", "mode="+*unlock); err != nil {
		return err
	}

	fmt.Fprintln(out, "Vault created:", path)
	if recoveryCode != "" {
		fmt.Fprintf(out, "Recovery code (shown once, store it safely): %s\n", recoveryCode)
		fmt.Fprintln(out, "Recovery also needs the recovery passphrase you just chose.")
	} else {
		fmt.Fprintln(out, noRecoveryWarning)
	}
	return nil
}

// addRecovery prompts for a recovery passphrase and returns the new recovery code.
func addRecovery(w *vaultcrypto.Wrapped, dataKey []byte) (string, error) {
	pass, err := askNew("Recovery passphrase (at least 12 characters)")
	if err != nil {
		return "", err
	}
	code, err := vaultcrypto.NewRecoveryCode()
	if err != nil {
		return "", err
	}
	return code, vaultcrypto.WrapRecovery(w, dataKey, code, pass)
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
	useKey := w.Mode == vaultcrypto.SSH || w.Mode == vaultcrypto.Both || (w.Mode == vaultcrypto.Either && identity != "")
	usePassword := w.Mode == vaultcrypto.Password || w.Mode == vaultcrypto.Both || (w.Mode == vaultcrypto.Either && identity == "")

	var u vaultcrypto.Unlock
	if usePassword {
		if u.Password, err = prompt.Secret("Password"); err != nil {
			return nil, err
		}
	}
	if useKey {
		if identity == "" {
			return nil, errors.New("this vault needs --ssh-identity (your SSH private key file)")
		}
		if u.SSHPrivateKey, err = os.ReadFile(identity); err != nil {
			return nil, err
		}
		u.SSHPassphrase = func() ([]byte, error) {
			p, err := prompt.Secret("SSH key passphrase")
			return []byte(p), err
		}
	}

	key, err := vaultcrypto.Unwrap(w, u)
	if err != nil {
		if logErr := s.Log("unlock_failed", ""); logErr != nil {
			return nil, logErr
		}
		return nil, err
	}
	return key, s.Log("unlock", "")
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
		fmt.Fprintln(out, "warning:", w)
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
	fmt.Fprintf(out, "added %d of %d accounts\n", added, len(accounts))
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
		fmt.Fprintf(out, "%d  %s\n", r.ID, account.Label(r.Account))
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
		fmt.Fprintf(out, "%s  %s  %s\n", e.Time.Format("2006-01-02 15:04:05"), e.Action, e.Detail)
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
