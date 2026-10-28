// Package migration decodes Google Authenticator otpauth-migration:// links.
package migration

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/rutvik24/otp-migration-helper/internal/otp"
	"google.golang.org/protobuf/encoding/protowire"
)

type Kind int

const (
	TOTP Kind = iota
	HOTP
)

type Account struct {
	Name, Issuer string
	Secret       []byte
	Algorithm    otp.Algorithm
	Digits       int
	Kind         Kind
	Counter      uint64
}

type Batch struct {
	Accounts    []Account
	BatchID     int32
	Size, Index int32
}

const scheme = "otpauth-migration"

func Decode(link string) (Batch, error) {
	u, err := url.Parse(strings.TrimSpace(link))
	if err != nil {
		return Batch{}, fmt.Errorf("invalid link: %w", err)
	}
	if u.Scheme != scheme {
		return Batch{}, fmt.Errorf("not an %s:// link", scheme)
	}
	data := strings.ReplaceAll(u.Query().Get("data"), " ", "+")
	if data == "" {
		return Batch{}, errors.New("link has no data parameter")
	}
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return Batch{}, fmt.Errorf("data is not valid base64: %w", err)
	}
	return parsePayload(raw)
}

func parsePayload(b []byte) (Batch, error) {
	var batch Batch
	err := walk(b, func(num protowire.Number, typ protowire.Type, v []byte, n uint64) error {
		switch {
		case num == 1 && typ == protowire.BytesType:
			a, err := parseAccount(v)
			if err != nil {
				return err
			}
			batch.Accounts = append(batch.Accounts, a)
		case num == 3 && typ == protowire.VarintType:
			batch.Size = int32(n)
		case num == 4 && typ == protowire.VarintType:
			batch.Index = int32(n)
		case num == 5 && typ == protowire.VarintType:
			batch.BatchID = int32(n)
		}
		return nil
	})
	if err != nil {
		return Batch{}, err
	}
	if len(batch.Accounts) == 0 {
		return Batch{}, errors.New("export contains no accounts")
	}
	return batch, nil
}

func parseAccount(b []byte) (Account, error) {
	a := Account{Digits: 6, Kind: TOTP}
	err := walk(b, func(num protowire.Number, typ protowire.Type, v []byte, n uint64) error {
		switch {
		case num == 1 && typ == protowire.BytesType:
			a.Secret = append([]byte(nil), v...)
		case num == 2 && typ == protowire.BytesType:
			a.Name = string(v)
		case num == 3 && typ == protowire.BytesType:
			a.Issuer = string(v)
		case num == 4 && typ == protowire.VarintType:
			a.Algorithm = algorithm(n)
		case num == 5 && typ == protowire.VarintType && n == 2:
			a.Digits = 8
		case num == 6 && typ == protowire.VarintType && n == 1:
			a.Kind = HOTP
		case num == 7 && typ == protowire.VarintType:
			a.Counter = n
		}
		return nil
	})
	return a, err
}

func algorithm(n uint64) otp.Algorithm {
	switch n {
	case 2:
		return otp.SHA256
	case 3:
		return otp.SHA512
	default:
		return otp.SHA1
	}
}

// walk calls fn for each field; v holds bytes fields, n holds varint fields.
func walk(b []byte, fn func(protowire.Number, protowire.Type, []byte, uint64) error) error {
	for len(b) > 0 {
		num, typ, tagLen := protowire.ConsumeTag(b)
		if tagLen < 0 {
			return protowire.ParseError(tagLen)
		}
		b = b[tagLen:]
		var v []byte
		var n uint64
		var valLen int
		switch typ {
		case protowire.VarintType:
			n, valLen = protowire.ConsumeVarint(b)
		case protowire.BytesType:
			v, valLen = protowire.ConsumeBytes(b)
		default:
			valLen = protowire.ConsumeFieldValue(num, typ, b)
		}
		if valLen < 0 {
			return protowire.ParseError(valLen)
		}
		b = b[valLen:]
		if err := fn(num, typ, v, n); err != nil {
			return err
		}
	}
	return nil
}
