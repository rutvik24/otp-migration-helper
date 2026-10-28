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

## Web app

    otpmh gui

Opens otpmh in your browser at a private local address (only this computer can reach it; the link works once). It has everything the command line has, in the Focus layout: your accounts on the left with a Copy button on every row, the selected account's live code on the right, and one shared clock because every code changes together.

- Create, unlock (password, SSH key, either, or both), recover, lock. It locks itself after 5 minutes without use.
- Import by dropping QR images, **scanning with your webcam**, or pasting decoded text (`otpauth-migration://` links and `otpauth://` URIs), in any order. Multi-QR exports are merged and missing codes are reported before anything is saved.
- Show a QR code for another authenticator app, export for Bitwarden or other managers, and see the activity log. Before a QR code, a secret or an export is shown, you confirm your credentials again (good for 2 minutes), so someone at an unlocked screen cannot just read them out.
- Light, Dark, or System (the default; it follows your operating system).

Nothing is loaded from the internet: fonts, scripts and the QR decoder are all part of the program. Camera access needs `localhost` or HTTPS.

## Docker and self-hosting

Images for every common CPU (amd64, arm64, arm/v7, arm/v6, 386, ppc64le, s390x, riscv64) are published to GitHub Container Registry:

    docker run -d --name otpmh -p 127.0.0.1:8080:8080 \
      -v otpmh-data:/data -e OTPMH_INSECURE_HTTP=true \
      ghcr.io/rutvik24/otp-migration-helper

Then open http://127.0.0.1:8080. On first start the container prints a one-time **setup code** (`docker logs otpmh`) that you enter when creating the vault; nobody who merely reaches the page can claim an empty server. Your vault lives in the `/data` volume.

`-p 127.0.0.1:8080:8080` publishes the port to this computer only, which is why plain HTTP is acceptable here. To use it from other devices, put it behind HTTPS instead:

- Behind a reverse proxy that terminates TLS: keep `OTPMH_INSECURE_HTTP=true`, publish the port only to the proxy, and set `OTPMH_ALLOWED_HOSTS=otp.example.com`.
- Or let it serve HTTPS itself: mount a certificate and key and set `OTPMH_TLS_CERT=/certs/fullchain.pem` and `OTPMH_TLS_KEY=/certs/privkey.pem` (no `OTPMH_INSECURE_HTTP`).

The server refuses to start over plain HTTP unless you opt in. In this mode the vault's own unlock is the login, wrong attempts are slowed and then blocked, and every outcome is written to the activity log. Browsers allow the webcam only on `localhost` or HTTPS; uploading images and pasting text work anywhere.

| Setting | Meaning |
| --- | --- |
| `OTPMH_LISTEN` | Address to listen on (the image sets `:8080`) |
| `OTPMH_VAULT_PATH` | Vault file (the image sets `/data/vault.db`) |
| `OTPMH_INSECURE_HTTP` | `true` to allow plain HTTP (TLS at a proxy, or loopback-only port) |
| `OTPMH_ALLOWED_HOSTS` | Comma-separated host names the server answers to |
| `OTPMH_TLS_CERT`, `OTPMH_TLS_KEY` | Serve HTTPS directly |

Passwords are never read from environment variables. To unlock with an SSH key in the web app, upload the key file or paste its text (plus its passphrase, if it has one). The key travels with the request, is used once, and is never saved; the server does not read key files from its own disk, so nothing needs mounting.

The image is a single static binary on an empty base (about 23 MB), runs as a non-root user, and has a built-in health check. GitHub creates new packages as private: after the first release, set the package to public once under the repository's Packages settings.

## Databases for self-hosting

By default the vault is a SQLite file. To keep it in **PostgreSQL** or **MySQL** (MariaDB works too) instead, point otpmh at the database:

    export OTPMH_DATABASE_URL='postgres://otpmh:PASSWORD@db.example:5432/otpmh?sslmode=require'
    # or: mysql://otpmh:PASSWORD@db.example:3306/otpmh?tls=true
    otpmh gui          # also works for `otpmh vault ...`

Use an empty database and a user that may create tables. otpmh creates its four tables on first use. The URL holds the database password, so prefer the environment, or a file named by `OTPMH_DATABASE_URL_FILE` (for Docker secrets), over the `--database-url` flag, which is visible in the process list. Flags win over the environment, then `OTPMH_DATABASE_URL`, then `OTPMH_DATABASE_URL_FILE`, then `OTPMH_VAULT_PATH`, then the default SQLite file.

Secrets are encrypted by otpmh before they reach any database, so whoever runs the database sees only ciphertext, names and issuers, and the activity log. Ready-to-use Compose files are in [`examples/`](examples): `docker compose -f examples/docker-compose.postgres.yml up -d` (or `.mysql.yml`) starts otpmh and its database, with the database password kept in Docker secrets.

To move an existing vault between databases, export it (`otpmh vault export`) and import into the new one.

## Development

    go vet ./... && go test ./...

Written from scratch; no code was taken from other OTP migration tools.

## License

MIT
