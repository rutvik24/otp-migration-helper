# Re-verification, database adapters, and uploaded keys — Design and plan

Builds on phases 1 to 3 (shipped through v0.4.0). The repo `CLAUDE.md` rules still apply.

## Requirements (the user's)
1. Seeing a QR code, the secret/setup link, or exporting must verify the user's authentication for the stored data again, at least.
2. Self-hosted users can run the vault on **PostgreSQL** or **MySQL** instead of the SQLite file.
3. In the web app the SSH key is **uploaded** (or pasted), together with its passphrase if it has one; the server never reads key files from its own disk.
4. Fix the Qodana findings (the paste had no details; see Calls).

## Design
**Re-verification (web app).** `POST /api/reauth` takes the same credentials the vault's mode asks for (password, SSH key + passphrase, or both) and checks them against the stored vault. A success lets that browser session use the sensitive endpoints (`/api/accounts/{id}/qr.png`, `/details`, `/api/export`) for 2 minutes; without it they answer `403 {"reauth": true}` and the page opens a "Confirm it's you" dialog, then retries the action. Failed attempts use the same rate limiter and are logged as `verify_failed`; successes as `verify`. Locking clears the verification.

**Uploaded keys.** Unlock and verification accept `sshPrivateKey` (the key's text) and `sshPassphrase`. The page reads an uploaded file in the browser (or takes pasted text) and sends the text over the same connection as the password. The server holds it only for the request, never writes it to disk or the log, and no longer accepts a server file path. The command line keeps `--ssh-identity` because it runs on the user's own machine.

**Database adapters.** `store` gains dialects for SQLite (default), PostgreSQL and MySQL/MariaDB, all pure Go (no CGO), chosen by the target string: a plain path means a SQLite file; `postgres://…`/`postgresql://…` and `mysql://…` select the other two. Only the SQL that differs lives in the dialect (placeholders, column types, upsert and insert-ignore). The data is the same: secrets are still encrypted by the application before they reach any database, so the database operator sees only ciphertext. `OTPMH_DATABASE_URL` (or a file named by `OTPMH_DATABASE_URL_FILE`, for Docker secrets) and `--database-url` select it; `--vault-path` keeps working for files. Tests run against real PostgreSQL and MySQL servers (Docker locally, service containers in CI).

## Non-goals
- Migrating an existing SQLite vault into another database (export and import covers it).
- Database-level encryption, TLS options beyond what the connection URL carries, or connection pooling tuning.

## Calls (mine)
- Verification lasts 2 minutes per browser session, not once per action, so viewing a QR and then its secret does not ask twice. It is one constant.
- A database password in `OTPMH_DATABASE_URL` is the operator's normal deployment secret; the vault's own password is still never read from the environment.
- Qodana: the paste held only severity labels. I ran staticcheck, gosec, errcheck, vet and govulncheck and fixed what was real (capitalized error strings); the gosec items that are deliberate or false positives (loopback-only health-check TLS skip, size-limited multipart parsing) stay, with the reasons in the summary.

## Tasks
1. `vault`: accept key text in `Creds`; `Verify`; sensitive-action window. Tests.
2. `gui`: reauth endpoint, guarded endpoints, key text instead of path, error-string cleanup. Tests.
3. `store`: dialects, PostgreSQL and MySQL drivers, target parsing, backend-parametrized tests; `vault`/CLI/`gui` take a target.
4. Web: key upload/paste component, "Confirm it's you" dialog, status of verification. Browser check.
5. Docs, Docker Compose examples, CI services, release v0.5.0.
