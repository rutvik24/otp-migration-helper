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
- Recovery that only the owner can complete. `vault init` creates two independent recovery secrets, shown once: a recovery code and a recovery passphrase the owner chooses. `vault recover` needs both. It lets the owner set a new password and/or SSH key and unlock mode, and then issues a new recovery code (the old one stops working). Creation can skip recovery only with an explicit `--no-recovery`, after a warning that a lost password or key then means a lost vault. Later phases (the GUI) reuse this path.
  - **No doubt, no entry:** recovery succeeds only when both secrets decrypt the vault key and its authentication check passes. Anything less, including a typo, fails the same way with the same generic message ("recovery failed"), with no hint about which part was wrong.
  - **Guessing is not feasible:** the recovery code carries 160 random bits and goes through a slow key-derivation function, so a wrong guess cannot be brute-forced offline either.
  - **Slowing abuse:** failed attempts are logged and trigger an increasing delay, then a lockout after 5 failures (24 hours). The lockout is a speed bump, not the protection: someone who copies the file can skip it, but still cannot open the vault without the two secrets.
  - **After success:** the CLI logs the event, issues new recovery secrets, and shows a notice. Any other unlock credentials stay valid only if the owner keeps them; recovery replaces them.
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
- Any recovery path that opens the vault on a partial or probable match, or that explains why an attempt failed.

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
- **Recovery secrets:** a 160-bit random recovery code (grouped base32) plus an owner-chosen recovery passphrase. Like `both` unlock mode, the data key is wrapped by one and the result is encrypted with the other, so both are required. A recovery passphrase has a minimum length, and the CLI rejects trivially weak ones.
- **Encryption:** the `age` format (filippo.io/age): a random data key encrypts each secret; the data key is wrapped using age. `password` uses age's passphrase mode; `ssh` uses age's SSH recipients and identities (including passphrase-protected keys); `either` stores two wrapped copies of the data key; `both` wraps the data key for the SSH key first and then encrypts that result with the password.
- **Commands:** `otpmh vault init --unlock password|ssh|either|both [--ssh-key PATH]`, `vault import [inputs…]`, `vault list`, `vault export --format bitwarden|passwords-csv|otpauth --yes`, `vault log`; and `--vault` on `show` and `live`.
- **Log storage:** an `activity_log` table in the same database.
- **Export columns:** the macOS CSV uses `Title,URL,Username,Password,Notes,OTPAuth`; verify against the current Passwords app before release.
