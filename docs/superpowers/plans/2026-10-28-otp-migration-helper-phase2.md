# OTP Migration Helper Phase 2 (Vault) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (the user chose native execution). Steps use checkbox (`- [ ]`) syntax.

**Goal:** A local encrypted vault with password/SSH/either/both unlock, owner-only recovery, an activity log, and exports.

**Architecture:** `internal/vaultcrypto` wraps a random data key with `age`; `internal/store` is the SQLite vault; `internal/export` formats accounts; `cmd/otpmh/vault.go` wires the `vault` subcommands and `--vault` flags. Secrets are encrypted per row; metadata is plaintext.

**Tech Stack:** `filippo.io/age` (+`agessh`), `modernc.org/sqlite`, `golang.org/x/term`, `golang.org/x/crypto` (XChaCha20-Poly1305), all `@latest`.

**Spec:** `docs/superpowers/specs/2026-10-28-phase2-vault-design.md`

## Global Constraints

- Follow `CLAUDE.md`: check every error (or `_ =` where harmless), run `govulncheck`, latest deps, anchored `.gitignore`.
- Explicit imports, no deprecated APIs, simplest change. No custom cipher or KDF: age scrypt for passwords, age SSH recipients for keys, XChaCha20-Poly1305 for row encryption.
- Passwords and key passphrases come from a no-echo terminal prompt, never flags or env vars.
- Vault file mode 0600; default path `<os.UserConfigDir()>/otpmh/vault.db`, override `--vault-path`.
- Logs never contain secrets, codes, passwords or recovery secrets.
- Recovery failures all return the single error text `recovery failed`.
- Commit messages end with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`.

## Review Focus

- Wrong password / wrong SSH key / corrupt wrapped blob: generic unlock error, no panic.
- Passphrase-protected SSH key unlocks; wrong passphrase fails.
- `both` mode fails with only one credential; `either` works with each.
- Recovery with wrong code, wrong passphrase, or both: identical `recovery failed`; lockout after 5 failures; old recovery code dead after success.
- Vault file created 0600.
- Plaintext export without `--yes` refuses and writes nothing.
- CSV export of names containing commas, quotes, newlines.
- Log contents never include any secret (test greps log text for base32 secret and password).
- HOTP counter advanced in `live` survives a restart.
- Importing the same export twice adds nothing new.

---

### Task 1: Key wrapping and row encryption (`internal/vaultcrypto`)

**Files:** Create `internal/vaultcrypto/vaultcrypto.go`, `internal/vaultcrypto/vaultcrypto_test.go`

**Interfaces:**
- Produces:
  - `type Mode string` with `Password`, `SSH`, `Either`, `Both` (values `"password"`, `"ssh"`, `"either"`, `"both"`).
  - `type Wrapped struct { Mode Mode; Password, SSH, Both, Recovery []byte }` (JSON-serialisable).
  - `type Setup struct { Mode Mode; Password string; SSHPublicKey string }` (authorized_keys line).
  - `type Unlock struct { Password string; SSHPrivateKey []byte; SSHPassphrase func() ([]byte, error) }`.
  - `func NewDataKey() ([]byte, error)` (32 random bytes).
  - `func Wrap(dataKey []byte, s Setup) (Wrapped, error)`; `func Unwrap(w Wrapped, u Unlock) ([]byte, error)` (error text `unlock failed` for every failure).
  - `func NewRecoveryCode() (string, error)` (160 random bits, base32, groups of 5 separated by `-`); `func WrapRecovery(w *Wrapped, dataKey []byte, code, passphrase string) error`; `func UnwrapRecovery(w Wrapped, code, passphrase string) ([]byte, error)` (error text `recovery failed`).
  - `func Seal(dataKey, plaintext []byte) ([]byte, error)`; `func Open(dataKey, sealed []byte) ([]byte, error)`.
  - `var workFactor = 18` used for every age scrypt recipient/identity (tests lower it).

- [ ] **Step 1: Write failing tests**: `TestSealOpen_RoundTrip`, `TestOpen_TamperedFails`; `TestWrap_Password` (right password unwraps, wrong fails with `unlock failed`); `TestWrap_SSH` (generated ed25519 key: unwrap with private PEM; wrong key fails); `TestWrap_SSHPassphrase` (key encrypted with `ssh.MarshalPrivateKeyWithPassphrase`; right passphrase works, wrong fails); `TestWrap_Either` (password alone works, key alone works); `TestWrap_Both` (both works; password alone fails; key alone fails); `TestWrap_CorruptBlob` (flip bytes → `unlock failed`); `TestRecovery_RoundTrip`; `TestRecovery_WrongCodeOrPassphraseSameError` (three cases return the identical error text); `TestRecoveryCode_Format` (5 groups of 5 base32 chars... 160 bits = 32 chars → 8 groups of 4? use groups of 4 separated by `-`, assert length and charset). Set `workFactor = 10` in `TestMain`.
- [ ] **Step 2: Run** `go test ./internal/vaultcrypto/...` — FAIL.
- [ ] **Step 3: Implement.** Password mode: age scrypt encrypt of the data key. SSH mode: age encrypt to `agessh.ParseRecipient`. Either: both blobs. Both: SSH-encrypt then scrypt-encrypt the result. SSH unlock: `agessh.ParseIdentity`; on `*ssh.PassphraseMissingError` use `agessh.NewEncryptedSSHIdentity` with the passphrase callback. Recovery: encrypt data key with scrypt(code), then scrypt(passphrase). Reject recovery passphrases shorter than 12 characters in `WrapRecovery`.
- [ ] **Step 4: Run** — PASS. **Step 5: Commit.**

### Task 2: SQLite store (`internal/store`)

**Files:** Create `internal/store/store.go`, `internal/store/store_test.go`

**Interfaces:**
- Consumes: `vaultcrypto.Wrapped/Seal/Open`, `migration.Account`.
- Produces:
  - `type Store struct{ … }`; `func Create(path string, w vaultcrypto.Wrapped) (*Store, error)` (file mode 0600, error if it exists); `func Open(path string) (*Store, error)`; `func (s *Store) Close() error`.
  - `func (s *Store) Wrapped() (vaultcrypto.Wrapped, error)`; `func (s *Store) SetWrapped(w vaultcrypto.Wrapped) error`.
  - `type Record struct { ID int64; migration.Account }`; `func (s *Store) AddAccounts(key []byte, accts []migration.Account) (added int, err error)` (dedupe on issuer+name+secret); `func (s *Store) Accounts(key []byte) ([]Record, error)`; `func (s *Store) SetCounter(id int64, counter uint64) error`.
  - `func (s *Store) Log(action, detail string) error`; `func (s *Store) Logs() ([]LogEntry, error)` with `type LogEntry struct { Time time.Time; Action, Detail string }`.
  - `func (s *Store) RecoveryState() (failures int, lockedUntil time.Time, err error)`; `func (s *Store) RecordRecoveryFailure(now time.Time) error` (5th failure locks 24h); `func (s *Store) ClearRecoveryFailures() error`.

- [ ] **Step 1: Write failing tests**: `TestCreate_Mode0600`, `TestCreate_ExistingFileErrors`, `TestAddAccounts_RoundTrip`, `TestAddAccounts_Dedupes`, `TestSecretNotPlaintextOnDisk` (read raw db bytes, assert the secret bytes are absent), `TestSetCounter_Persists` (close and reopen), `TestLog_Order`, `TestRecoveryLockout` (4 failures: not locked; 5th: locked until now+24h; Clear resets).
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement** with `database/sql` and the `modernc.org/sqlite` driver; tables `meta`, `accounts`, `activity_log`, `recovery_state`. **Step 4: Run** — PASS. **Step 5: Commit.**

### Task 3: Prompts and `vault init` / `import` / `list` / `log`

**Files:** Create `internal/prompt/prompt.go`, `internal/prompt/prompt_test.go`, `cmd/otpmh/vault.go`, `cmd/otpmh/vault_test.go`; Modify `cmd/otpmh/main.go` (dispatch `vault`, usage text).

**Interfaces:**
- Produces: `func prompt.Secret(label string) (string, error)` (no-echo via `term.ReadPassword` on the terminal; errors if stdin is not a terminal); a package var `prompt.Secret` replaceable in tests; `func runVault(args []string, stdin io.Reader, out io.Writer) error` dispatching `init|import|list|log|export|recover`; helper `func openVault(path string, out io.Writer) (*store.Store, []byte, error)` that reads the wrapped blob, prompts for the credentials its mode needs (password; SSH private key path via `--ssh-key` then passphrase if the key is encrypted), unwraps, logs `unlock` or `unlock_failed`.
- `vault init --unlock password|ssh|either|both [--ssh-key PATH.pub] [--no-recovery] [--vault-path P]`: prompts twice for the password when needed, creates the vault, and (unless `--no-recovery`) prompts for a recovery passphrase (twice), prints the recovery code once with the warning, logs `create`.

- [ ] **Step 1: Write failing tests** with `prompt.Secret` replaced by a scripted fake and `--vault-path` in `t.TempDir()`: `TestVaultInit_PasswordThenList` (init, import a test link, list shows the label), `TestVaultInit_PasswordMismatchErrors`, `TestVaultInit_PrintsRecoveryCodeOnce`, `TestVaultInit_NoRecoveryWarns`, `TestVaultImport_TwiceAddsOnce`, `TestVaultList_WrongPasswordGenericError`, `TestVaultLog_NoSecrets` (log text contains neither the base32 secret nor the password), `TestPromptSecret_NonTerminalErrors`.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement** the signatures above. `import` takes the same inputs as `show` via `source.Load`, then `AddAccounts`, logging `import` with the count only. `list` prints labels and kinds only. **Step 4: Run** — PASS. **Step 5: Commit.**

### Task 4: `--vault` on `show` and `live`, persisted HOTP counters

**Files:** Modify `cmd/otpmh/show.go`, `cmd/otpmh/live.go`, `internal/tui/live.go`, `internal/tui/live_test.go`, `cmd/otpmh/vault_test.go`

**Interfaces:**
- Consumes: `openVault`, `store.Accounts`, `store.SetCounter`.
- Produces: `tui.Live(accounts []migration.Account, onAdvance func(index int, counter uint64)) error` (nil allowed; called after each HOTP advance); `--vault` and `--vault-path` flags on `show` and `live` (`--vault` with no inputs loads from the vault).

- [ ] **Step 1: Write failing tests**: `TestLive_OnAdvanceCalled` (model-level: pressing `n` on a HOTP account invokes the callback with the new counter), `TestShow_FromVault` (init, import, `show --vault --all` prints the URL), `TestVaultHotpCounterPersists` (advance via the store as the callback would, reopen, counter retained).
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** Log `show` with the count of accounts only. **Step 4: Run** — PASS. **Step 5: Commit.**

### Task 5: Exports (`internal/export`, `vault export`)

**Files:** Create `internal/export/export.go`, `internal/export/export_test.go`; Modify `cmd/otpmh/vault.go`, `cmd/otpmh/vault_test.go`

**Interfaces:**
- Produces: `func Bitwarden(accts []migration.Account) ([]byte, error)` (`{"encrypted":false,"folders":[],"items":[{"type":1,"name":…,"login":{"username":…,"totp":<otpauth URL>}}]}`); `func PasswordsCSV(accts []migration.Account) ([]byte, error)` (header `Title,URL,Username,Password,Notes,OTPAuth`, empty URL/Password/Notes); `func OTPAuthList(accts []migration.Account) []byte` (one URL per line). `vault export --format bitwarden|passwords-csv|otpauth --yes [--out FILE]`; without `--yes` it errors and writes nothing; `--out` files are created 0600; logs `export` with format and count.

- [ ] **Step 1: Write failing tests**: `TestBitwarden_Shape` (unmarshal and check fields), `TestPasswordsCSV_EscapesCommasQuotesNewlines` (parse with `encoding/csv` and compare), `TestOTPAuthList`, `TestVaultExport_RequiresYes` (error, no file), `TestVaultExport_FileMode0600`.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement** with `encoding/json` and `encoding/csv`. **Step 4: Run** — PASS. **Step 5: Commit.**

### Task 6: Recovery

**Files:** Modify `cmd/otpmh/vault.go`, `cmd/otpmh/vault_test.go`

**Interfaces:**
- Consumes: `vaultcrypto.UnwrapRecovery/Wrap/WrapRecovery`, `store.RecoveryState/RecordRecoveryFailure/ClearRecoveryFailures/SetWrapped`.
- Produces: `vault recover [--unlock password|ssh|either|both] [--ssh-key PATH.pub] [--vault-path P]`: refuses while locked (`recovery failed`), prompts for the recovery code and passphrase, on any failure records it, logs `recovery_failed`, and returns exactly `recovery failed`; on success prompts for the new credentials, re-wraps the data key, issues a new recovery code (printing it once), clears failures, logs `recovery`.

- [ ] **Step 1: Write failing tests**: `TestRecover_Success` (new password works, old password no longer does), `TestRecover_NewRecoveryCodeOldDead`, `TestRecover_WrongCodeWrongPassphraseSameMessage`, `TestRecover_LockoutAfterFiveFailures` (6th attempt with the correct secrets still fails with the same message while locked), `TestRecover_NoRecoveryVault` (vault created with `--no-recovery` → `recovery failed`), `TestRecover_LogsNoSecrets`.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS. **Step 5: Commit.**

### Task 7: Docs, CI, release

**Files:** Modify `README.md`, `CLAUDE.md` (no change expected); tag `v0.2.0`.

- [ ] **Step 1: README**: document `vault` commands, unlock modes, recovery, exports (and that exports are unencrypted), and the lost-credentials warning.
- [ ] **Step 2: Run** `go get -u ./... && go mod tidy`, `go vet ./...`, `go test ./...`, `govulncheck`, `go list -m -u all` — all clean.
- [ ] **Step 3: Push**, wait for green CI (all jobs), then tag `v0.2.0` (annotated) and confirm the release has binaries.
