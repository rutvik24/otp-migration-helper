# OTP Migration Helper Phase 3 (Web Interface, Docker) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (native execution, chosen earlier). Steps use checkbox (`- [ ]`) syntax.

**Goal:** `otpmh gui`: a browser interface served from the binary with full vault support, webcam/image/text scanning, light/dark blue "Focus" design, plus a multi-architecture Docker image on GHCR.

**Architecture:** `internal/vault` holds credential-based vault operations (the CLI delegates to it); `internal/gui` is an HTTP server (security middleware, session manager, JSON API, embedded `web/`); `web/` is plain HTML/CSS/JS with embedded fonts and a vendored QR decoder; a Dockerfile and GitHub workflow publish to GHCR.

**Tech Stack:** Go stdlib `net/http`, `embed`; existing packages; Docker Buildx; vendored `jsQR` (Apache-2.0) and the Bricolage Grotesque / Martian Mono variable fonts (SIL OFL) from their npm packages.

**Spec:** `docs/superpowers/specs/2026-10-28-phase3-gui-design.md`

## Global Constraints

- Follow `CLAUDE.md` (check every error, close resources, `say`/`sayln` for CLI status output, govulncheck, errcheck clean, latest deps, anchored `.gitignore`).
- No labels or text reading "GUI" anywhere in the interface or its copy. The app is just called otpmh.
- No network access from the page: no CDN, fonts, scripts or analytics; everything embedded. CSP `default-src 'self'`.
- Interface copy: sentence case, active voice, specific actions ("Copy code", "Copied", "Lock"), errors say what happened and how to fix it. Keep the approved Focus design, tokens and light/dark/system theme from the mockup `.superpowers/brainstorm/*/content/focus-light-dark.html`.
- Responses never contain secrets before unlock; every response sends `Cache-Control: no-store`.
- Commit messages end with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`.

## Review Focus

- Request with a wrong `Host` header (DNS rebinding) is rejected; so are requests without the session cookie (401) and POSTs without the CSRF header (403).
- Local mode: the launch token works once; reusing it fails.
- Server mode: refuses to start over plain HTTP without `--insecure-http`; repeated bad unlocks get delayed then blocked, and every outcome is logged.
- Idle sessions lock after 5 minutes and the data key is dropped; locking invalidates the cookie.
- Image upload that is not an image, is huge, or has no QR: clear error, nothing saved.
- Pasted garbage, partial multi-QR exports, and duplicates: preview reports them and commit saves only new accounts.
- Export refuses without the explicit confirmation field.
- QR image endpoint and codes endpoint return 401 when locked.
- HOTP "Next" persists across lock/unlock.
- Reduced motion, keyboard focus, and phone width render without overflow.

---

### Task 1: Shared vault service (`internal/vault`) and CLI refactor

**Files:** Create `internal/vault/vault.go`, `internal/vault/vault_test.go`; Modify `cmd/otpmh/vault.go`.

**Interfaces:**
- Produces:
  - `type Creds struct { Password, SSHIdentityPath string; SSHPassphrase func() ([]byte, error) }`
  - `type CreateOptions struct { Setup vaultcrypto.Setup; RecoveryPassphrase string; NoRecovery bool }`
  - `func Exists(path string) bool`; `func Mode(path string) (vaultcrypto.Mode, error)`
  - `func Create(path string, o CreateOptions) (recoveryCode string, err error)` (creates parent dir 0700, logs `create`)
  - `type Session struct{...}`; `func Open(path string, c Creds) (*Session, error)` (logs `unlock`/`unlock_failed`; error text `unlock failed`); `func (s *Session) Close() error`
  - `func (s *Session) Records() ([]store.Record, error)`, `Import(accts []migration.Account) (added int, err error)` (logs `import`), `SetCounter(id int64, counter uint64) error`, `Export(format string) ([]byte, error)` (logs `export`; formats `bitwarden`, `passwords-csv`, `otpauth`), `Log(action, detail string) error`, `Logs() ([]store.LogEntry, error)`
  - `func Recover(path, code, passphrase string, newSetup vaultcrypto.Setup, newRecoveryPassphrase string) (newCode string, err error)` (lockout and logging exactly as the CLI recovery; error text `recovery failed`)
  - `func Logs(path string) ([]store.LogEntry, error)` (no unlock needed)

- [ ] **Step 1: Write failing tests** in `internal/vault`: `TestCreateOpenPassword`, `TestOpenWrongPasswordGeneric`, `TestCreateModes` (ssh/either/both using generated ed25519 keys, identity file on disk, encrypted key with passphrase callback), `TestImportExportRoundTrip`, `TestRecoverRotatesAndLocksOut` (success rotates, five failures lock, same message), `TestLogsNeverContainSecrets`. Use `vaultcrypto.SetWorkFactorForTests(10)`.
- [ ] **Step 2: Run** `go test ./internal/vault/...` — FAIL.
- [ ] **Step 3: Implement** by moving the logic out of `cmd/otpmh/vault.go` (unlock, recover, create, export) behind these signatures; the CLI keeps prompting and printing and calls the service.
- [ ] **Step 4: Run** `go test ./...` — all PASS, including every existing CLI vault test unchanged (they prove the refactor kept behavior).
- [ ] **Step 5: Commit.**

### Task 2: QR from bytes, and text/URI resolution for the web

**Files:** Modify `internal/qrcode/qrcode.go`, `internal/qrcode/qrcode_test.go`, `internal/source/source.go`, `internal/source/source_test.go`

**Interfaces:**
- Produces: `func qrcode.Read(r io.Reader, name string) ([]string, error)` (`ReadFile` calls it); `func qrcode.PNG(text string, size int) ([]byte, error)`; `func source.Preview(texts []string) (accounts []migration.Account, warnings []string, err error)` (texts only: migration links and otpauth URIs; no file paths).

- [ ] **Step 1: Write failing tests**: `TestRead_FromBytes`, `TestRead_NotAnImageNamesIt`, `TestPNG_DecodesBack`, `TestPreview_MixedTextsAnyOrder`, `TestPreview_RejectsFilePaths` (a path string is an error, not a file read — the web must never read server files by name).
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS. **Step 5: Commit.**

### Task 3: Server core and security (`internal/gui`)

**Files:** Create `internal/gui/server.go`, `internal/gui/security.go`, `internal/gui/session.go`, `internal/gui/server_test.go`

**Interfaces:**
- Produces:
  - `type Config struct { VaultPath, Listen string; Port int; TLSCert, TLSKey string; AllowedHosts []string; InsecureHTTP, Remote bool }`
  - `func New(cfg Config) (*Server, error)` (errors: Remote + plain HTTP without `InsecureHTTP`); `func (s *Server) Handler() http.Handler`; `func (s *Server) Run(ctx context.Context, open func(url string)) error`
  - Middleware order: host check → token/cookie auth (local mode; unlock-issued cookie in server mode) → CSRF header `X-Requested-With: otpmh` on non-GET → headers (`Cache-Control: no-store`, CSP, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`).
  - Session store: random 32-byte ids, idle expiry 5 minutes (injectable clock), holds `*vault.Session`; `Lock` closes it.
  - Unlock rate limit per client address: delay doubling from 1s after 3 failures, blocked 15 minutes after 10.
  - `GET /healthz` (no auth, returns `ok`).

- [ ] **Step 1: Write failing tests** with `httptest`: `TestHost_WrongHostRejected`, `TestAPI_NoCookie401`, `TestCSRF_PostWithoutHeader403`, `TestLocalToken_WorksOnce`, `TestHeaders_NoStoreAndCSP`, `TestRemote_PlainHTTPRefusedWithoutOptIn`, `TestSession_ExpiresAfterIdle` (fake clock), `TestUnlockRateLimit_DelaysThenBlocks`.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS. **Step 5: Commit.**

### Task 4: JSON API

**Files:** Create `internal/gui/api.go`, `internal/gui/api_test.go`

**Interfaces:**
- Consumes: Task 1–3.
- Produces routes (JSON; errors `{"error": "<message>"}`):
  - `GET /api/status` → `{exists, mode, unlocked}` (works locked)
  - `POST /api/vault` create `{mode, password, sshPublicKey, recoveryPassphrase, noRecovery}` → `{recoveryCode}`
  - `POST /api/unlock` `{password, sshIdentityPath, sshPassphrase}`; `POST /api/lock`
  - `GET /api/codes` → `{secondsLeft, accounts:[{id,label,issuer,name,kind,digits,code,counter}]}`
  - `POST /api/accounts/{id}/next` (HOTP: advance and persist)
  - `GET /api/accounts/{id}/qr.png`; `GET /api/accounts/{id}/details` → `{url, secret}` (secret only on explicit request)
  - `POST /api/decode-image` (multipart, 10 MB limit) → `{texts}`
  - `POST /api/import/preview` `{texts}` → `{accounts:[{label,kind}], warnings}`; `POST /api/import/commit` `{texts}` → `{added}`
  - `POST /api/export` `{format, confirm:true}` → file body with `Content-Disposition`
  - `POST /api/recover` `{code, passphrase, mode, password, sshPublicKey, newRecoveryPassphrase}` → `{recoveryCode}`
  - `GET /api/log`

- [ ] **Step 1: Write failing tests** driving the full flow over `httptest` (workFactor lowered): `TestFlow_CreateUnlockImportCodes`, `TestCodes_Locked401`, `TestUnlock_WrongPasswordGeneric`, `TestImportPreview_WarnsOnMissingBatch`, `TestImportCommit_DedupesAndSaves`, `TestDecodeImage_NotImageErrors`, `TestDecodeImage_ReturnsText`, `TestExport_RequiresConfirm`, `TestHotpNext_Persists`, `TestRecover_RotatesAndOldPasswordFails`, `TestDetails_ReturnsSecretOnlyWhenUnlocked`, `TestLog_HasNoSecrets`.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS. **Step 5: Commit.**

### Task 5: Web interface

**Files:** Create `internal/gui/web/index.html`, `web/app.css`, `web/app.js` (plus small modules `clock.js`, `scan.js`, `theme.js`), `web/fonts/*.woff2`, `web/vendor/jsQR.js`; `internal/gui/assets.go` (`//go:embed web`); Modify `internal/gui/server.go` to serve it.

**Interfaces:**
- Produces the screens from the spec: create vault, unlock (fields shown per vault mode), recover, main Focus view (list with per-row Copy/Next + "Copied", code panel, shared clock bar, Show QR dialog, Export dialog with unencrypted warning), Import (drop images, paste text, webcam scan with live preview, progress "N of M codes read", merged account preview, "Save N accounts"), Activity log, theme switch System/Light/Dark remembered in `localStorage`.

- [ ] **Step 1: Write failing tests**: `TestAssets_IndexServedAndNoExternalURLs` (the embedded index, CSS and JS contain no `http://` or `https://` URLs except inside the vendored decoder's license comment), `TestAssets_NoGUILabel` (no "GUI" text in embedded HTML), `TestAssets_FontsEmbedded` (woff2 files present and served with the right type).
- [ ] **Step 2: Run** — FAIL. **Step 3: Build the files** following the approved mockup tokens; fonts and jsQR fetched from their npm packages at build time and committed. **Step 4: Run** — PASS.
- [ ] **Step 5: Browser check** with Playwright against a real running server in a temp dir: create vault, unlock, import by pasted text and by dropped image, copy, theme switch (system/light/dark), lock; take screenshots in both themes and at phone width; fix what looks wrong. Webcam is verified with Chromium's fake-camera flags and a generated QR video frame.
- [ ] **Step 6: Commit.**

### Task 6: `otpmh gui` command

**Files:** Create `cmd/otpmh/gui.go`, add tests to `cmd/otpmh/gui_test.go`; Modify `cmd/otpmh/main.go` (dispatch, usage).

**Interfaces:** `otpmh gui [--vault-path P] [--port N] [--no-open] [--listen ADDR] [--tls-cert F --tls-key F] [--allowed-host H] [--insecure-http]`; env fallbacks `OTPMH_LISTEN`, `OTPMH_VAULT_PATH`, `OTPMH_INSECURE_HTTP`, `OTPMH_ALLOWED_HOSTS` (never secrets); prints the launch URL; opens the browser unless `--no-open`; stops cleanly on interrupt.

- [ ] **Step 1: Write failing tests**: `TestGui_FlagParsingAndEnv`, `TestGui_RemotePlainHTTPRefused`, `TestGui_StartsAndServesHealthz` (random port, then cancel).
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement** (browser opening via `open`/`xdg-open`/`rundll32` through the existing runner pattern). **Step 4: Run** — PASS. **Step 5: Commit.**

### Task 7: Docker image, GHCR publishing, release

**Files:** Create `Dockerfile`, `.dockerignore`, `.github/workflows/docker.yml`; Modify `.goreleaser.yaml` (extra Linux architectures), `README.md`, `CLAUDE.md` (add the UI-copy and no-external-asset rules).

- [ ] **Step 1: Dockerfile**: multi-stage; builder `--platform=$BUILDPLATFORM golang:<latest>-alpine` cross-compiles with `CGO_ENABLED=0`, `GOOS=linux`, `GOARCH=$TARGETARCH`, `GOARM` from `TARGETVARIANT`; final `scratch` with CA certs, tzdata, a non-root numeric user, `/data` volume, `EXPOSE 8080`, `HEALTHCHECK` via the binary (`otpmh healthcheck`), `ENTRYPOINT ["/otpmh","gui","--listen",":8080","--vault-path","/data/vault.db","--no-open"]`.
- [ ] **Step 2: docker.yml**: on `v*` tags, QEMU not needed; `docker/setup-buildx-action`, `docker/login-action` to `ghcr.io` with `GITHUB_TOKEN` (`packages: write`), `docker/metadata-action` tags (`X.Y.Z`, `X.Y`, `latest`), `docker/build-push-action` with `platforms: linux/amd64,linux/arm64,linux/arm/v7,linux/arm/v6,linux/386,linux/ppc64le,linux/s390x,linux/riscv64`.
- [ ] **Step 3: Verify locally** (if Docker is available): build for the host platform, run it, and fetch `/healthz`; always run `docker buildx build --check` or equivalent lint. Report honestly if Docker is not installed.
- [ ] **Step 4: README**: GUI, scanning, Docker quick start (`docker run -p 127.0.0.1:8080:8080 -v otpmh-data:/data -e OTPMH_INSECURE_HTTP=true ghcr.io/rutvik24/otp-migration-helper`), self-hosting behind HTTPS, camera/HTTPS note, making the GHCR package public once.
- [ ] **Step 5: Final checks**: `go get -u ./... && go mod tidy`, `go vet`, `go test ./...`, errcheck, govulncheck, `go list -m -u all`.
- [ ] **Step 6: Push, wait for green CI on that exact commit, tag `v0.4.0`, confirm the release and the Docker workflow outcome, and the image manifest platforms with `docker buildx imagetools inspect` if available.
