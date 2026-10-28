# Project rules

## Keep Qodana and vulnerability scans clean

Qodana (GoLand) flags these on this repo; do not introduce them.

- **Unhandled errors (`GoUnhandledErrorResult`).** Every call that returns an error is checked.
  - Return or `t.Fatal` the error, including `Close`, `Remove`, `WriteFile`, `Encode` and `os.Create`.
  - Where the failure truly cannot matter (cleanup after another error, closing a read-only file), discard it explicitly: `_ = os.Remove(path)`. Never leave it bare.
  - Build strings with `b.WriteString(fmt.Sprintf(...))`, not `fmt.Fprintf(&builder, ...)`.
- **Vulnerable dependencies (`VulnerableLibrariesLocal`).**
  - Before committing a dependency change, run `go run golang.org/x/vuln/cmd/govulncheck@latest ./...` and upgrade until it reports none. This includes indirect modules and the Go standard library version in `go.mod`.
  - After `go get`, run `go get <indirect module>@latest` for any flagged indirect module, then `go mod tidy`.
- **Always use the latest dependency versions.**
  - Add dependencies with `@latest`, and run `go get -u ./... && go mod tidy` before each push.
  - Pin an older version only when strictly required (a newer one breaks the build or API). Record why in a comment next to the `require` line in `go.mod`.
  - Check with `go list -m -u all`.
- **Never ignore source by bare name.** In `.gitignore`, anchor binaries and build output (`/otpmh`, `/dist/`). A bare `otpmh` also hid `cmd/otpmh`. After adding files, check `git status` shows every new package.

Before pushing: `go vet ./... && go test ./...` plus the govulncheck command above, all clean.
