# otpmh - OTP Migration Helper

Move your Google Authenticator accounts to another device or app. `otpmh` decodes a Google Authenticator export and shows, for each account you pick, a QR code another authenticator can scan, the `otpauth://` URL and the base32 secret for pasting into desktop apps, and a live view of rolling codes.

Everything runs locally. Nothing is sent over the network and nothing is saved to disk.

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

Exports with several QR codes: pass every image (`otpmh show a.png b.png`). Missing codes are reported.

TOTP and HOTP accounts are supported. In `live`, a HOTP code advances only when you press `n`.

### macOS scanning

    otpmh scan                      # drag a box around each QR code on screen
    otpmh scan --method shortcut    # use the Shortcuts app instead
    otpmh install-shortcuts         # add both shortcuts to the Shortcuts app

macOS asks you to click "Add Shortcut" once per shortcut. On other systems pass a QR image path.

## Development

    go vet ./... && go test ./...

Written from scratch; no code was taken from other OTP migration tools.

## License

MIT
