package migration

import (
	"encoding/base32"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/rutvik24/otp-migration-helper/internal/otp"
)

const uriScheme = "otpauth"

var base32NoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)

// DecodeURI parses a single-account otpauth://totp|hotp/... URI, the text a
// regular account QR code holds. Parameters this tool cannot honor (a period
// other than 30s, digits other than 6 or 8, MD5) are errors, never silently
// wrong codes.
func DecodeURI(s string) (Account, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil {
		return Account{}, fmt.Errorf("invalid otpauth URI: %w", err)
	}
	if u.Scheme != uriScheme {
		return Account{}, fmt.Errorf("not an %s:// URI", uriScheme)
	}

	a := Account{Digits: 6}
	switch strings.ToLower(u.Host) {
	case "totp":
		a.Kind = TOTP
	case "hotp":
		a.Kind = HOTP
	default:
		return Account{}, fmt.Errorf("unsupported otpauth type %q", u.Host)
	}

	q := u.Query()
	if a.Secret, err = decodeSecret(q.Get("secret")); err != nil {
		return Account{}, err
	}
	if a.Name, a.Issuer, err = parseLabel(u.EscapedPath()); err != nil {
		return Account{}, err
	}
	if issuer := q.Get("issuer"); issuer != "" {
		a.Issuer = issuer
	}
	if a.Algorithm, err = uriAlgorithm(q.Get("algorithm")); err != nil {
		return Account{}, err
	}
	switch q.Get("digits") {
	case "", "6":
	case "8":
		a.Digits = 8
	default:
		return Account{}, fmt.Errorf("unsupported digits %q (use 6 or 8)", q.Get("digits"))
	}
	if p := q.Get("period"); p != "" && p != "30" {
		return Account{}, fmt.Errorf("unsupported period %q (only 30 seconds)", p)
	}
	if c := q.Get("counter"); c != "" {
		if a.Counter, err = strconv.ParseUint(c, 10, 64); err != nil {
			return Account{}, fmt.Errorf("invalid counter %q", c)
		}
	}
	return a, nil
}

func decodeSecret(s string) ([]byte, error) {
	s = strings.ToUpper(strings.NewReplacer(" ", "", "=", "", "-", "").Replace(s))
	if s == "" {
		return nil, errors.New("otpauth URI has no secret")
	}
	secret, err := base32NoPadding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("secret is not valid base32: %w", err)
	}
	return secret, nil
}

// parseLabel splits "Issuer:Name" on the first literal colon; colons inside
// either part are percent-encoded.
func parseLabel(escaped string) (name, issuer string, err error) {
	label := strings.TrimPrefix(escaped, "/")
	issuerPart, namePart, hasIssuer := strings.Cut(label, ":")
	if !hasIssuer {
		issuerPart, namePart = "", label
	}
	if name, err = url.PathUnescape(namePart); err != nil {
		return "", "", err
	}
	if issuer, err = url.PathUnescape(issuerPart); err != nil {
		return "", "", err
	}
	return strings.TrimSpace(name), strings.TrimSpace(issuer), nil
}

func uriAlgorithm(name string) (otp.Algorithm, error) {
	switch strings.ToUpper(name) {
	case "", "SHA1":
		return otp.SHA1, nil
	case "SHA256":
		return otp.SHA256, nil
	case "SHA512":
		return otp.SHA512, nil
	}
	return otp.SHA1, fmt.Errorf("unsupported algorithm %q", name)
}
