# OTP Migration Helper — Design

## Intent
Moving Google Authenticator accounts to a new device or app means handling one opaque `otpauth-migration://` export. This CLI turns that export into things a person can actually use: a per-account QR code that another authenticator can scan, the `otpauth://` URL and base32 secret to paste into desktop apps, and a live TOTP view.

It is inspired by mshegolev/otp-migration-tool. All code is written from scratch; nothing is copied from that repo.

## Goals
- Decode a Google Authenticator export (`otpauth-migration://offline?data=...`) fully offline.
- Inputs: a pasted link, a QR image path (every OS), or scanning (macOS only).
- Multi-QR exports: read each QR one at a time, merge by batch id, and warn if a batch is missing.
- Show an account's name, issuer, `otpauth://` URL, base32 secret and a terminal QR code. The user picks accounts from an interactive list, or passes `--all`.
- Live view: full-screen like `man`, stays open until `q`. For the chosen accounts it shows the current code, seconds remaining and a draining progress bar (red near the end), and refreshes at each 30s boundary.
- macOS: one command installs two shortcuts into the Shortcuts app: (a) a Shortcuts-app QR scan that feeds results to the CLI one by one, (b) an on-screen capture flow driven by the CLI itself (`screencapture` region select). The user clicks "Add Shortcut" once; macOS requires this.
- HOTP accounts are supported alongside TOTP (RFC 4226). Show/QR/URL work as for TOTP. In the live view a HOTP account shows its code at the counter from the export, advanced only on an explicit keypress. Since phase 1 saves nothing, the advanced counter is not persisted until phase 2.
- CI on every push/PR; tagged releases with cross-platform binaries.

## Non-goals
- No network access, remote telemetry or cloud sync. Telemetry means local logs only, and logs never contain secrets or codes.
- Phase 1 writes nothing to disk. Saving comes in phase 2.
- Phase 1 has no direct import into other apps' stores; the user scans or pastes.
- No GUI in phase 1.

## Phases
1. **Core CLI (v0.1):** everything under Goals. No storage.
2. **Encrypted vault:** local SQLite store with secrets encrypted by a password or SSH key. Local activity log. Export to Bitwarden and other TOTP-capable password managers, and to the macOS Passwords app, via their import formats. Persists HOTP counters.
3. **GUI:** desktop or local web UI, after phases 1 and 2 are stable.
Each phase gets its own design, plan and release.

## Anti-goals
- Leaking secrets: nothing printed unless the user asked for it, and a one-line warning that QR codes and secrets grant account access.
- Copying code from the reference repo.

## Constraints
- Go, public repo `github.com/rutvik24/otp-migration-helper`.
- Project rules apply: simplest change, explicit imports, no deprecated APIs.
- Cross-platform builds; macOS-only features are build-tagged or runtime-gated and give a clear message elsewhere.

## Decisions (user's)
Hash/QR/URL per account, `--all` shows everything with QR, live `man`-style view with timers and progress bars, both macOS shortcut options installed by a single command, new public repo under `rutvik24`, CI/CD plus a release.

## Builder's calls (mine; adjust freely)
- **Command shape:** `otpmh show [input...] [--all]`, `otpmh live [input...] [--all]`, `otpmh scan [--method shortcut|capture]` (macOS), `otpmh install-shortcuts` (macOS). Inputs come from args or stdin.
- **Decoding:** hand-written protobuf wire parsing of the export payload (secret, name, issuer, algorithm, digits, type, counter; batch fields).
- **TOTP/HOTP:** own RFC 6238 and RFC 4226 implementations (SHA1/256/512, 6 or 8 digits, 30s period), tested against RFC vectors.
- **Libraries:** a QR encode/decode library, a QR image reader, and a TUI library (Bubble Tea) chosen at planning time.
- **Shortcut install:** generate a shortcut file, sign it with `shortcuts sign`, then `open` it.
- **CI/CD:** GitHub Actions running vet and tests on Linux/macOS/Windows; GoReleaser on `v*` tags; first release `v0.1.0`.
- **Posture:** secrets live in memory only.
