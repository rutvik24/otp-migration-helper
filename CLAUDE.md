# Project rules

## Keep Qodana and vulnerability scans clean

Qodana (GoLand) flags these on this repo; do not introduce them.

- **Unhandled errors (`GoUnhandledErrorResult`).** Every call that returns an error is checked.
  - Return or `t.Fatal` the error, including `Close`, `Remove`, `WriteFile`, `Encode` and `os.Create`.
  - Where the failure truly cannot matter (cleanup after another error, closing a read-only file), discard it explicitly: `_ = os.Remove(path)`. Never leave it bare.
  - Build strings with `b.WriteString(fmt.Sprintf(...))`, not `fmt.Fprintf(&builder, ...)`.
  - In `cmd/otpmh`, status messages use `say`/`sayln`. Output that is the point of a command (secrets, lists, exports) returns its write error: `if _, err := fmt.Fprintf(...); err != nil { return err }`.
  - Check with `go run github.com/kisielk/errcheck@latest ./...`; it must print nothing.
- **Close every resource on every path (`GoResourceLeak`).** If a write to an `age` writer, file or similar fails, close it before returning the error (`_ = w.Close()`).
- **Vulnerable dependencies (`VulnerableLibrariesLocal`).**
  - Before committing a dependency change, run `go run golang.org/x/vuln/cmd/govulncheck@latest ./...` and upgrade until it reports none. This includes indirect modules and the Go standard library version in `go.mod`.
  - After `go get`, run `go get <indirect module>@latest` for any flagged indirect module, then `go mod tidy`.
- **Always use the latest dependency versions.**
  - Add dependencies with `@latest`, and run `go get -u ./... && go mod tidy` before each push.
  - Pin an older version only when strictly required (a newer one breaks the build or API). Record why in a comment next to the `require` line in `go.mod`.
  - Check with `go list -m -u all`.
- **Never ignore source by bare name.** In `.gitignore`, anchor binaries and build output (`/otpmh`, `/dist/`). A bare `otpmh` also hid `cmd/otpmh`. After adding files, check `git status` shows every new package.

- **The web interface stays offline and honest.**
  - Everything (fonts, scripts, the QR decoder) is embedded; no CDN, no external URL. `internal/gui/assets_test.go` enforces this and the strict Content-Security-Policy (no inline scripts or styles, no `innerHTML`).
  - The interface never shows the text "GUI". The app is just called otpmh.
  - Build DOM with `h()` and `setChildren()`, never the bare `replaceChildren` (it turns `null` and arrays into text).
  - Return empty lists as `[]`, not `null`, from the JSON API.
  - Interface copy: sentence case, active voice, specific buttons ("Copy code", "Copied"), errors say what happened and what to do.
  - Check UI changes in a real browser (Playwright), light and dark and phone width, before claiming they work.
- **Every platform must compile.** Releases and the container image target amd64, arm64, arm/v7, arm/v6, 386, ppc64le, s390x, riscv64 (plus Windows, macOS, FreeBSD). Keep integer constants and sizes portable (use `int64` for values above 2^31). CI's `cross-build` job checks this.
- **Verify the right CI run.** After pushing, wait for the run whose `headSha` equals `git rev-parse HEAD`; do not trust the latest run in the list.

Before pushing: `go vet ./... && go test ./...` plus the govulncheck command above, all clean.
