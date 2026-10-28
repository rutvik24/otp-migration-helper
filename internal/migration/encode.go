package migration

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"

	"github.com/rutvik24/otp-migration-helper/internal/otp"
	"google.golang.org/protobuf/encoding/protowire"
)

// MaxPerCode is the most accounts one QR code may hold. Google Authenticator
// itself puts up to 10 in a code; more would make the code too dense to scan.
const MaxPerCode = 10

// DefaultPerCode keeps each code small enough to read from a terminal.
const DefaultPerCode = 5

// Encode turns accounts into Google Authenticator "import accounts" links
// (otpauth-migration://offline?data=…), splitting them over several links of at
// most perCode accounts each. Every link carries the same batch id and its
// position, so the app can tell when it has read them all. The links are the
// text of the QR codes that Google Authenticator, and many other apps, import.
func Encode(accounts []Account, perCode int) ([]string, error) {
	if len(accounts) == 0 {
		return nil, errors.New("no accounts to export")
	}
	if perCode < 1 || perCode > MaxPerCode {
		return nil, fmt.Errorf("accounts per QR code must be between 1 and %d", MaxPerCode)
	}
	batchID, err := newBatchID()
	if err != nil {
		return nil, err
	}
	size := (len(accounts) + perCode - 1) / perCode

	links := make([]string, 0, size)
	for index := 0; index < size; index++ {
		end := min((index+1)*perCode, len(accounts))
		payload, err := encodePayload(accounts[index*perCode:end], size, index, batchID)
		if err != nil {
			return nil, err
		}
		links = append(links, scheme+"://offline?data="+url.QueryEscape(base64.StdEncoding.EncodeToString(payload)))
	}
	return links, nil
}

func newBatchID() (int32, error) {
	var raw [4]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return 0, err
	}
	return int32(binary.BigEndian.Uint32(raw[:]) & 0x7fffffff), nil
}

// encodePayload writes Google's MigrationPayload message.
func encodePayload(accounts []Account, size, index int, batchID int32) ([]byte, error) {
	var b []byte
	for _, a := range accounts {
		params, err := encodeAccount(a)
		if err != nil {
			return nil, err
		}
		b = protowire.AppendTag(b, 1, protowire.BytesType)
		b = protowire.AppendBytes(b, params)
	}
	for _, f := range []struct {
		num protowire.Number
		val int64
	}{{2, 1}, {3, int64(size)}, {4, int64(index)}, {5, int64(batchID)}} { // version 1, then the batch fields
		b = protowire.AppendTag(b, f.num, protowire.VarintType)
		b = protowire.AppendVarint(b, uint64(f.val))
	}
	return b, nil
}

// encodeAccount writes Google's OtpParameters message.
func encodeAccount(a Account) ([]byte, error) {
	if len(a.Secret) == 0 {
		return nil, fmt.Errorf("%q has no secret", a.Name)
	}
	var algorithm uint64
	switch a.Algorithm {
	case otp.SHA1:
		algorithm = 1
	case otp.SHA256:
		algorithm = 2
	case otp.SHA512:
		algorithm = 3
	default:
		return nil, fmt.Errorf("%q uses an algorithm Google Authenticator cannot import", a.Name)
	}
	var digits uint64
	switch a.Digits {
	case 6:
		digits = 1
	case 8:
		digits = 2
	default:
		return nil, fmt.Errorf("%q has %d digits; Google Authenticator imports 6 or 8", a.Name, a.Digits)
	}
	kind := uint64(2) // TOTP
	if a.Kind == HOTP {
		kind = 1
	}

	var b []byte
	b = protowire.AppendTag(b, 1, protowire.BytesType)
	b = protowire.AppendBytes(b, a.Secret)
	b = protowire.AppendTag(b, 2, protowire.BytesType)
	b = protowire.AppendString(b, a.Name)
	if a.Issuer != "" {
		b = protowire.AppendTag(b, 3, protowire.BytesType)
		b = protowire.AppendString(b, a.Issuer)
	}
	for _, f := range []struct {
		num protowire.Number
		val uint64
	}{{4, algorithm}, {5, digits}, {6, kind}} {
		b = protowire.AppendTag(b, f.num, protowire.VarintType)
		b = protowire.AppendVarint(b, f.val)
	}
	if a.Kind == HOTP {
		b = protowire.AppendTag(b, 7, protowire.VarintType)
		b = protowire.AppendVarint(b, a.Counter)
	}
	return b, nil
}
