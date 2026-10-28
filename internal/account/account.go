// Package account formats decoded accounts for display and export.
package account

import (
	"encoding/base32"
	"net/url"
	"strconv"
	"strings"

	"github.com/rutvik24/otp-migration-helper/internal/migration"
)

var noPadding = base32.StdEncoding.WithPadding(base32.NoPadding)

func Base32(secret []byte) string {
	return noPadding.EncodeToString(secret)
}

// Label is the human-readable "Issuer:Name" (or just Name).
func Label(a migration.Account) string {
	if a.Issuer == "" {
		return a.Name
	}
	return a.Issuer + ":" + a.Name
}

func URL(a migration.Account) string {
	kind := "totp"
	q := url.Values{}
	q.Set("secret", Base32(a.Secret))
	q.Set("algorithm", a.Algorithm.Name())
	q.Set("digits", strconv.Itoa(a.Digits))
	if a.Kind == migration.HOTP {
		kind = "hotp"
		q.Set("counter", strconv.FormatUint(a.Counter, 10))
	} else {
		q.Set("period", "30")
	}

	label := escapeLabel(a.Name)
	if a.Issuer != "" {
		q.Set("issuer", a.Issuer)
		label = escapeLabel(a.Issuer) + ":" + label
	}
	return "otpauth://" + kind + "/" + label + "?" + q.Encode()
}

// escapeLabel keeps ':' for the issuer separator only, so escape it inside parts.
func escapeLabel(s string) string {
	return strings.ReplaceAll(url.PathEscape(s), ":", "%3A")
}
