# otpmh - OTP Migration Helper

Move your Google Authenticator accounts to another device or app. `otpmh` decodes a Google Authenticator export and shows, for each account you pick, a QR code another authenticator can scan, the `otpauth://` URL and the base32 secret for pasting into desktop apps, and a live view of rolling codes.

Everything runs locally and nothing is sent over the network. Nothing is saved unless you create a vault (below).

> **Keep output secret.** Anyone with a QR code or secret can generate your login codes.

## Install

Download a binary from the [releases page](https://github.com/rutvik24/otp-migration-helper/releases), or:

    go install github.com/rutvik24/otp-migration-helper/cmd/otpmh@latest

## Usage

In Google Authenticator choose *Transfer accounts > Export accounts*. Give `otpmh` the exported QR image or its `otpauth-migration://...` link:

    otpmh show export.png              # pick accounts interactively
    otpmh show --all export.png        # every account: URL, secret, QR
    otpmh live export.png              # live codes with timers; q quits
    echo 'otpauth-migration://offline?data=...' | otpmh show --all

Inputs can be QR image paths, or the text a QR code decodes to (an `otpauth-migration://...` export link, or a single-account `otpauth://totp/...` URI), mixed in any order:

    otpmh show --all a.png 'otpauth-migration://offline?data=...' b.png 'otpauth://totp/Acme:me?secret=...'

Exports with several QR codes: pass every image or text (`otpmh show a.png b.png`). Missing codes are reported. Single-account URIs must use a 30-second period, 6 or 8 digits and SHA1/256/512; anything else is rejected rather than giving wrong codes.

TOTP and HOTP accounts are supported. In `live`, a HOTP code advances only when you press `n`.

### macOS scanning

    otpmh scan                      # drag a box around each QR code on screen
    otpmh scan --method shortcut    # use the Shortcuts app instead
    otpmh install-shortcuts         # add both shortcuts to the Shortcuts app

macOS asks you to click "Add Shortcut" once per shortcut. On other systems pass a QR image path.

## Encrypted vault

Keep your accounts locally instead of re-importing the Google export each time. Secrets are encrypted; names and issuers are stored in the clear.

    otpmh vault init --unlock password            # or: ssh | either | both
    otpmh vault init --unlock both --ssh-key ~/.ssh/id_ed25519.pub
    otpmh vault import export.png                 # add accounts (duplicates are skipped)
    otpmh vault list
    otpmh show --vault --all                      # QR/URL/secret from the vault
    otpmh live --vault                            # live codes; HOTP counters are saved
    otpmh vault log                               # local activity log (never holds secrets)

Unlock modes: `password`; `ssh` (an SSH key, passphrase-protected keys work); `either` (password or key); `both` (password and key). Unlock with an SSH key by adding `--ssh-identity ~/.ssh/id_ed25519` (the private key file). Passwords and passphrases are typed at a hidden prompt, never on the command line.

The vault lives at `<user config dir>/otpmh/vault.db` (override with `--vault-path`), file mode 0600 (Windows does not use Unix modes; keep the vault in your user profile).

### Recovery

`vault init` prints a one-time recovery code and asks for a recovery passphrase. Recovery needs both. It also rotates the vault's data key and re-encrypts every account, so the old key stops working on the recovered vault:

    otpmh vault recover --unlock password

Any wrong or partial answer fails with the same message, and five failures lock recovery for 24 hours. A successful recovery sets new credentials and issues a new recovery code (the old one stops working). With `--no-recovery`, a lost password or key means the vault is gone.

### Export to a password manager

    otpmh vault export --format bitwarden --yes --out bitwarden.json
    otpmh vault export --format passwords-csv --yes --out passwords.csv   # macOS Passwords app and other CSV importers
    otpmh vault export --format otpauth --yes                             # one otpauth:// URL per line

Exports are **unencrypted**, so `--yes` is required. Delete the file after importing it.

## Development

    go vet ./... && go test ./...

Written from scratch; no code was taken from other OTP migration tools.

## License

MIT
