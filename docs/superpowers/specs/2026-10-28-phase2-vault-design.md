# Phase 2: Encrypted Vault — Design

Builds on `2026-10-28-otp-migration-helper-design.md` (phase 1, shipped as v0.1.1). All of its rules still apply, including the repo `CLAUDE.md` (check every error, run govulncheck, anchor `.gitignore` entries).

## Intent
Phase 1 forgets everything on exit. Phase 2 lets the user keep their accounts locally, protected at rest, then show, run live, or export them without the original Google export.

## Goals
- A local SQLite vault holding accounts. Secrets are encrypted; names and issuers are stored in the clear (they are not secrets).
- Unlock mode chosen at vault creation:
  - `password`: a password unlocks it.
  - `ssh`: an SSH private key unlocks it (ed25519 or RSA). Keys protected by their own passphrase work; the CLI prompts for it.
  - `either`: the password or the SSH key unlocks it.
  - `both`: the password and the SSH key are both required.
- Existing commands read from the vault: `show` and `live` accept `--vault` instead of a link or image.
- Import into the vault from the same inputs as phase 1 (link, image, macOS scan).
- Recovery: `vault init` generates a recovery code, shown once, that can open the vault independently of the password and SSH key. `vault recover` uses it to set a new password and/or SSH key and unlock mode. Creation can skip it only with an explicit `--no-recovery`, after a warning that a lost password or key then means a lost vault. Later phases (the GUI) reuse the same recovery path.
- Persist HOTP counters, so `live` advances them across runs.
- Local activity log (the user's "telemetry"): who/what/when for create, import, show, export, unlock failures. Never secrets or codes. Nothing leaves the machine.
- Exports, each requiring an explicit confirmation flag because the output is unencrypted:
  - Bitwarden JSON (unencrypted import format; `login.totp` holds the otpauth URI).
  - A CSV for the macOS Passwords app (and other managers that import CSV).
  - A plain `otpauth://` list.

## Non-goals
- No cloud sync, remote telemetry, or network access.
- No ssh-agent integration and no hardware-key (FIDO) SSH keys.
- No automatic import into other apps; the user imports the exported file.
- No GUI (phase 3).
- No key rotation in this phase. Changing the unlock mode is possible only through recovery (below).

## Anti-goals
- Secrets or codes in logs, error messages, or temp files.
- Silently writing a plaintext export.
- Inventing a cipher or key-derivation scheme.

## Constraints
- Go, pure-Go SQLite driver so cross-platform builds keep working without CGO.
- Prompts for passwords and key passphrases read from the terminal without echo; no passwords on the command line or in environment variables.
- Vault file permissions 0600; default path `<os.UserConfigDir()>/otpmh/vault.db`, overridable with `--vault-path`.
- Latest dependency versions unless strictly required otherwise (see `CLAUDE.md`).
- Must pass CI plus govulncheck, and Qodana-clean (no unhandled errors).

## Decisions (user's)
Unlock modes password / ssh / either / both, chosen at creation; SSH keys with passphrases supported; local logs only; exports to Bitwarden, the macOS Passwords app and other TOTP-capable managers.

## Builder's calls (mine; adjust freely)
- **Password handling (correction to the request):** TOTP/HOTP secrets must be readable to produce codes, so they cannot be stored as one-way hashes the way bcrypt stores passwords. Instead the password goes through a slow, memory-hard key-derivation function (age's scrypt) to produce the key that encrypts the data key. bcrypt is a password hash, not a key-derivation function (72-byte input limit, no key output), so I did not use it. Argon2id is the alternative if you prefer it.
- **Recovery code:** 160 random bits shown as grouped base32. It is a further wrapper of the data key, stored like the other unlock methods.
- **Encryption:** the `age` format (filippo.io/age): a random data key encrypts each secret; the data key is wrapped using age. `password` uses age's passphrase mode; `ssh` uses age's SSH recipients and identities (including passphrase-protected keys); `either` stores two wrapped copies of the data key; `both` wraps the data key for the SSH key first and then encrypts that result with the password.
- **Commands:** `otpmh vault init --unlock password|ssh|either|both [--ssh-key PATH]`, `vault import [inputs…]`, `vault list`, `vault export --format bitwarden|passwords-csv|otpauth --yes`, `vault log`; and `--vault` on `show` and `live`.
- **Log storage:** an `activity_log` table in the same database.
- **Export columns:** the macOS CSV uses `Title,URL,Username,Password,Notes,OTPAuth`; verify against the current Passwords app before release.
