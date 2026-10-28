# Phase 3: GUI — Design

Builds on phases 1 and 2 (shipped through v0.3.0). Their rules still apply, including the repo `CLAUDE.md` (check every error, close resources, run govulncheck, latest dependencies, anchored `.gitignore`).

## Intent
A beautiful, offline desktop-style interface for the vault: see live codes, copy them, show a QR to scan on another device, import, export, and recover, without the terminal.

## Goals
- `otpmh gui` starts a server bound to `127.0.0.1` on a random port and opens the user's browser. The page is served from the binary itself.
- The GUI does everything the CLI's inputs do:
  - Scan QR codes with the **webcam** (live camera preview, each QR is read one at a time and merged into the account list, with a progress note such as "1 of 3 codes read" for multi-QR exports).
  - Drop or choose **QR images**, in any number and order.
  - Paste **decoded text**: `otpauth-migration://` links and `otpauth://` URIs, mixed with images and camera scans in any order.
  - Decode the export and show what was found (accounts, missing QR codes) before saving to the vault.
- **Docker and self-hosting:** an official multi-architecture image on GitHub Container Registry (`ghcr.io/rutvik24/otp-migration-helper`) that runs the GUI. Quick start: `docker run -p 127.0.0.1:8080:8080 -v otpmh-data:/data ...`. Images are built for linux/amd64, arm64, arm/v7, arm/v6, 386, ppc64le, s390x and riscv64.
- The approved "Focus" design (mockups: `.superpowers/brainstorm/*/content/focus-light-dark.html`):
  - Left: account list; each row has its own Copy button (HOTP rows have "Next"). The button changes to "Copied" after use.
  - Right: a large blue code panel for the selected account, name and issuer, "New code in N seconds", and Copy code / Show QR / Export actions.
  - One shared 30-second clock along the bottom of the code panel; it turns amber for the last 5 seconds. Reduced-motion users get a static bar plus the seconds text.
- Blue theme with Light and Dark; default is System (follows the OS and its changes), with a System / Light / Dark switch in the top bar. The choice is remembered in the browser.
- Screens: unlock (password, SSH key path, or both, per the vault's mode), first-run vault creation (with the recovery code shown once), recovery, main view, import (drop QR images, paste text), Show QR, export (with the unencrypted warning and explicit confirmation), activity log.
- Auto-lock after 5 minutes without interaction, and a Lock button. Locking forgets the data key in memory.
- Works without a mouse (keyboard focus visible, labelled controls), and down to phone width.

## Non-goals
- No network access of any kind: no CDN fonts, scripts or analytics. The fonts (Bricolage Grotesque, Martian Mono, both SIL OFL) and all assets are embedded in the binary.
- No user accounts, cloud sync, or built-in internet exposure. Self-hosting is supported (see Constraints), but the default is local only.
- No native window toolkit (Electron, Wails, Fyne) in this phase.
- No new vault features; the GUI uses what phases 1 and 2 provide.

## Anti-goals
- Secrets (codes, secrets, QR images, passwords) cached by the browser, logged, or sent to anything but the user's own browser tab.
- Another local program or web page being able to read the vault by guessing the port.

## Constraints
- **Security, local mode (default):** loopback only; a random one-time session token in the launch URL, exchanged for an HttpOnly SameSite=Strict cookie; every request checks the cookie and a `Host` header of `127.0.0.1:<port>` (blocks DNS rebinding); state-changing requests also need a per-session CSRF header; `Content-Security-Policy: default-src 'self'` (plus `media-src`/camera permission for the scan page only); `Cache-Control: no-store` on every response.
- **Security, server mode (`--listen ADDR`, used by the Docker image):** there is no launch URL, so the vault's own unlock is the login. A session cookie (HttpOnly, SameSite=Strict, `Secure` over HTTPS) is issued only after a successful unlock, with the same CSRF and CSP rules. Unlock attempts are rate-limited per client address (exponential delay, then a temporary block), recovery keeps its own lockout, and every outcome is written to the activity log. The server refuses to start in server mode over plain HTTP unless the operator opts in with `--insecure-http` / `OTPMH_INSECURE_HTTP=true` (for example behind a TLS proxy or bound to the host's loopback). `--tls-cert` and `--tls-key` enable HTTPS directly. `--allowed-host` lists the accepted `Host` names.
- **Webcam:** browsers expose the camera only on `localhost` or HTTPS, so remote self-hosting needs HTTPS for scanning. Image upload and pasted text work everywhere.
- **Container:** non-root user, read-only root filesystem friendly, vault file at `/data/vault.db` on a volume, SSH keys (if used) mounted read-only and referenced by path, a health endpoint. Passwords never go in environment variables, image layers or command lines.
- Pure Go, no CGO; plain HTML, CSS and JavaScript with no build step and no npm.
- The vault logic used by the CLI and the GUI is shared, not duplicated (see calls below).
- Passwords and passphrases are only ever typed into the page and sent over loopback; they are never stored and never logged.

## Decisions (user's)
Focus layout with a Copy button on every list row; blue theme; Light and Dark with System as the default.

## Builder's calls (mine; adjust freely)
- **Architecture:** a new `internal/gui` package (HTTP handlers + embedded `web/` files) and a new `internal/vault` package that holds the vault operations that take explicit credentials instead of prompting (open/unlock, init, import, list, counters, export, recover). The CLI's `vault` commands are refactored to call `internal/vault`, so behavior and tests are shared.
- **Frontend:** vanilla JS modules and CSS custom properties for the theme tokens from the mockups; the clock is one `requestAnimationFrame` loop; codes are computed in Go and sent each second with the seconds remaining.
- **QR decoding:** in the browser, the frames and images never leave the page; I'll use the browser's `BarcodeDetector` where it exists and fall back to a vendored, embedded copy of an open-source JavaScript QR decoder (jsQR, Apache-2.0). The decoded text is then sent to the server, which parses it with the same Go code as the CLI.
- **Image build:** a multi-stage Dockerfile cross-compiles the static binary on the build host for each target (`TARGETARCH`/`TARGETVARIANT`), then copies it into `scratch` with CA certificates and tzdata, so every architecture builds quickly without emulation. A GitHub Actions workflow with Buildx publishes versioned and `latest` tags to GHCR on every release tag. GoReleaser also gains the extra Linux architectures. GitHub requires the package to be set to public once, in the package settings after the first push; I can't do that for you.
- **SSH key:** the unlock form takes the private key file path (a browser cannot read a path from a file picker) and an optional passphrase field. The key is read by the server.
- **Clipboard:** the page copies with the browser clipboard API on a user click only.
- **Command:** `otpmh gui [--vault-path P] [--port N] [--no-open] [--listen ADDR] [--tls-cert F --tls-key F] [--allowed-host H] [--insecure-http]`.
- **Release:** v0.4.0.
