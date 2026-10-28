# OTP Migration Helper Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Go CLI (`otpmh`) that decodes Google Authenticator exports and shows per-account QR/URL/secret, plus a live TOTP/HOTP view and macOS scanning.

**Architecture:** Small `internal/` packages with one job each (otp, migration, account, qrcode, source, tui, macos) wired by a thin `cmd/otpmh` using stdlib `flag` subcommands. Everything is local; secrets live in memory only.

**Tech Stack:** Go; `github.com/skip2/go-qrcode` (encode), `github.com/makiuchi-d/gozxing` (decode), `github.com/charmbracelet/bubbletea` + `bubbles/progress` + `lipgloss` (TUI). Pin the latest stable versions with `go get` at implementation time.

**Spec:** `docs/superpowers/specs/2026-10-28-otp-migration-helper-design.md`

## Global Constraints

- Module path `github.com/rutvik24/otp-migration-helper`; binary name `otpmh`; repo public under `rutvik24`.
- Code is written from scratch. Do not read or copy mshegolev/otp-migration-tool.
- Project rules: simplest change, explicit imports (no fully qualified names in bodies), no deprecated APIs.
- No network calls anywhere. Secrets never written to disk, logs or history; print them only when the command's purpose is to show them, with a one-line warning.
- TOTP period 30s, digits 6 or 8, algorithms SHA1/SHA256/SHA512; HOTP per RFC 4226.
- macOS-only features are gated at runtime (`runtime.GOOS == "darwin"`) with a clear message elsewhere; the code must still compile on Linux/Windows.
- Commit messages end with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`.

## Review Focus

- Truncated/garbage/non-migration link: clear error, no panic.
- Link whose `data=` is URL-encoded (`%2B`, `%3D`) or has `+` turned into space: still decodes.
- Multi-QR export with a missing or duplicated batch: warns which batch is missing; duplicates not listed twice.
- Names with `:`, spaces, unicode, or empty issuer: valid `otpauth://` URL, label escaped.
- Terminal narrower than the QR or list: live view and QR output degrade without crashing.
- `live` with non-TTY stdout: exits with an error, not escape-code garbage.
- QR image that is blank, tiny, or not an image: clear error naming the path.
- HOTP account in `live`: counter advances only on keypress.

---

### Task 1: Repo scaffold and OTP algorithms

**Files:**
- Create: `go.mod`, `.gitignore`, `internal/otp/otp.go`, `internal/otp/otp_test.go`
- Run: `git init`, `go mod init github.com/rutvik24/otp-migration-helper`

**Interfaces:**
- Produces: `type Algorithm int` (`SHA1`, `SHA256`, `SHA512`); `func HOTP(secret []byte, counter uint64, digits int, alg Algorithm) string`; `func TOTP(secret []byte, t time.Time, period uint64, digits int, alg Algorithm) string`; `func SecondsLeft(t time.Time, period uint64) int`.

- [ ] **Step 1: Write failing tests** `TestHOTP_RFC4226` (secret `12345678901234567890`, 6 digits: counter 0→`755224`, 1→`287082`), `TestTOTP_RFC6238` (t=59, 8 digits: SHA1→`94287082`; SHA256 with secret `12345678901234567890123456789012`→`46119246`; SHA512 with the 64-byte secret `1234567890123456789012345678901234567890123456789012345678901234`→`90693936`), `TestSecondsLeft` (t=59, period 30 → 1; t=60 → 30).
- [ ] **Step 2: Run** `go test ./internal/otp/...` — expect FAIL (undefined).
- [ ] **Step 3: Implement** the signatures above with `crypto/hmac` and dynamic truncation; zero-pad to `digits`.
- [ ] **Step 4: Run** `go test ./internal/otp/...` — expect PASS.
- [ ] **Step 5: Commit** (`git init` first; `.gitignore` ignores the built binary and `dist/`).

### Task 2: Migration link decoder

**Files:** Create `internal/migration/migration.go`, `internal/migration/migration_test.go`

**Interfaces:**
- Consumes: `otp.Algorithm`.
- Produces: `type Kind int` (`TOTP`, `HOTP`); `type Account struct { Name, Issuer string; Secret []byte; Algorithm otp.Algorithm; Digits int; Kind Kind; Counter uint64 }`; `type Batch struct { Accounts []Account; BatchID int32; Size, Index int32 }`; `func Decode(link string) (Batch, error)`.

- [ ] **Step 1: Write failing tests** using a test helper that builds a payload with `google.golang.org/protobuf/encoding/protowire` (fields: payload 1=repeated params, 3=batch_size, 4=batch_index, 5=batch_id; params 1=secret, 2=name, 3=issuer, 4=algorithm 1/2/3=SHA1/256/512, 5=digits 1/2=6/8, 6=type 1/2=HOTP/TOTP, 7=counter): `TestDecode_TotpAccount`, `TestDecode_HotpCounter`, `TestDecode_DefaultsWhenUnspecified` (algorithm/digits 0 → SHA1/6), `TestDecode_URLEncodedData` (`%2B`,`%3D`), `TestDecode_PlusAsSpace`, `TestDecode_Errors` (wrong scheme, empty data, bad base64, truncated protobuf → error, no panic).
- [ ] **Step 2: Run** — expect FAIL.
- [ ] **Step 3: Implement `Decode`**: parse URL, require scheme `otpauth-migration`, take `data`, replace spaces with `+`, base64-decode, walk fields with `protowire`.
- [ ] **Step 4: Run** — expect PASS.
- [ ] **Step 5: Commit.**

### Task 3: Account formatting

**Files:** Create `internal/account/account.go`, `internal/account/account_test.go`

**Interfaces:**
- Consumes: `migration.Account`.
- Produces: `func URL(a migration.Account) string` (`otpauth://totp|hotp/<Issuer:Name>?secret=…&issuer=…&algorithm=…&digits=…&period=30|counter=N`); `func Base32(secret []byte) string` (no padding); `func Label(a migration.Account) string`.

- [ ] **Step 1: Write failing tests**: `TestURL_Totp` (exact string for a known account), `TestURL_HotpIncludesCounter`, `TestURL_EscapesLabel` (name with `:`, space, unicode, and empty issuer), `TestBase32_NoPadding`.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement** with `net/url` and `encoding/base32`. **Step 4: Run** — PASS. **Step 5: Commit.**

### Task 4: QR render and read

**Files:** Create `internal/qrcode/qrcode.go`, `internal/qrcode/qrcode_test.go`

**Interfaces:**
- Produces: `func Render(text string) (string, error)` (terminal-printable block characters); `func ReadFile(path string) ([]string, error)` (all QR payloads found in the image).

- [ ] **Step 1: Write failing tests**: `TestRender_NotEmpty`, `TestReadFile_RoundTrip` (encode text to a PNG in `t.TempDir()` via go-qrcode, read it back, equal), `TestReadFile_Errors` (missing file, non-image file, blank image → error that names the path).
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement** `Render` with go-qrcode's small string output; `ReadFile` with `image.Decode` plus gozxing's QR reader. **Step 4: Run** — PASS. **Step 5: Commit.**

### Task 5: Input collection and batch merging

**Files:** Create `internal/source/source.go`, `internal/source/source_test.go`

**Interfaces:**
- Consumes: `migration.Decode`, `qrcode.ReadFile`.
- Produces: `func Load(inputs []string, stdin io.Reader) ([]migration.Account, []string, error)` returning accounts and warnings. Each input is a migration link or an image path; with no inputs it reads links from stdin, one per line. Batches merge by `BatchID`; accounts deduplicate on `(Issuer, Name, Secret)`.

- [ ] **Step 1: Write failing tests**: `TestLoad_LinkArg`, `TestLoad_ImagePath`, `TestLoad_StdinLines`, `TestLoad_MissingBatchWarns` (2-of-3 batches → a warning naming the missing batch index), `TestLoad_DuplicateAccountOnce`.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS. **Step 5: Commit.**

### Task 6: CLI skeleton, `show`, picker

**Files:** Create `cmd/otpmh/main.go`, `cmd/otpmh/show.go`, `internal/tui/picker.go`, `cmd/otpmh/show_test.go`

**Interfaces:**
- Consumes: `source.Load`, `account.URL/Base32/Label`, `qrcode.Render`.
- Produces: subcommand dispatch (`show`, `live`, `scan`, `install-shortcuts`, `help`); `func runShow(args []string, stdin io.Reader, out io.Writer) error`; `func tui.Pick(accounts []migration.Account) ([]migration.Account, error)` (interactive multi-select).

- [ ] **Step 1: Write failing tests** against `runShow` with a fake link: `TestShow_AllPrintsEveryAccountWithQR` (output contains each account's URL, base32 secret and a QR block; also the one-line secrecy warning), `TestShow_NoInputsNoStdinErrors`, `TestUnknownSubcommand`.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement**: `--all` skips the picker; otherwise `tui.Pick`. **Step 4: Run** — PASS. **Step 5: Commit.**

### Task 7: Live view

**Files:** Create `internal/tui/live.go`, `internal/tui/live_test.go`, `cmd/otpmh/live.go`

**Interfaces:**
- Consumes: `otp.TOTP/HOTP/SecondsLeft`.
- Produces: `func tui.Live(accounts []migration.Account) error` (full screen, `q` quits, arrows move selection, `n` advances the selected HOTP counter, ticks every second, bar turns red at ≤5s); `runLive(args, stdin, out)` using `--all` or `tui.Pick`.

- [ ] **Step 1: Write failing tests** on the Bubble Tea model's `Update`/`View` without a terminal: `TestLive_TotpShowsCodeAndSeconds`, `TestLive_RolloverChangesCode` (fake clock across a 30s boundary), `TestLive_HotpAdvancesOnlyOnN`, `TestLive_QQuits`, `TestLive_NarrowWidthDoesNotPanic` (width 10), and `TestRunLive_NonTTYErrors`.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement** with an injectable clock in the model. **Step 4: Run** — PASS. **Step 5: Commit.**

### Task 8: macOS scanning and shortcut install

**Files:** Create `internal/macos/macos.go`, `internal/macos/macos_test.go`, `cmd/otpmh/scan.go`

**Interfaces:**
- Produces: `func CaptureRegion() (string, error)` (runs `screencapture -i -x` to a temp file, returns the path, caller deletes it); `func InstallShortcuts() error`; `func Supported() bool`. `scan --method capture` loops "capture → `qrcode.ReadFile` → decode" until the batch is complete or the user cancels. `scan --method shortcut` runs the installed shortcut with `shortcuts run`, one QR per run, same loop.

- [ ] **Step 1: Write failing tests** with an injectable command runner: `TestSupported_FalseOffDarwin`, `TestInstall_SignsThenOpens` (runner sees `shortcuts sign` then `open`, in that order), `TestScan_UnsupportedOSMessage`.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement**; build the shortcut plist in code, sign it with `shortcuts sign --mode anyone`, then `open` it.
- [ ] **Step 4: Run** unit tests — PASS.
- [ ] **Step 5: Verify on a real Mac** that the generated shortcuts install and scan a QR code. The Shortcuts scan action is the least certain part. If it cannot be generated reliably, keep the capture method as the working path and report the gap instead of shipping a broken shortcut.
- [ ] **Step 6: Commit.**

### Task 9: CI, release, README, publish

**Files:** Create `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `.goreleaser.yaml`, `README.md`, `LICENSE` (MIT)

- [ ] **Step 1: ci.yml**: on push/PR, matrix ubuntu/macos/windows, `go vet ./...` and `go test ./...`.
- [ ] **Step 2: release.yml + .goreleaser.yaml**: on tag `v*`, build `otpmh` for darwin/linux/windows × amd64/arm64 with archives and checksums.
- [ ] **Step 3: README**: usage for every subcommand, the secrecy warning, macOS notes, and the clean-room note.
- [ ] **Step 4: Run** `go vet ./... && go test ./...` locally — expect PASS; `goreleaser check` if installed.
- [ ] **Step 5: Create the repo and push** (authorized: public, under `rutvik24`): `gh repo create rutvik24/otp-migration-helper --public --source=. --push`.
- [ ] **Step 6: Confirm CI is green**, then tag and push `v0.1.0` and confirm the release has binaries.
