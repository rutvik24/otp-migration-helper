// Package otp implements HOTP (RFC 4226) and TOTP (RFC 6238).
package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"time"
)

type Algorithm int

const (
	SHA1 Algorithm = iota
	SHA256
	SHA512
)

func (a Algorithm) newHash() func() hash.Hash {
	switch a {
	case SHA256:
		return sha256.New
	case SHA512:
		return sha512.New
	default:
		return sha1.New
	}
}

// Name returns the algorithm name used in otpauth:// URLs.
func (a Algorithm) Name() string {
	switch a {
	case SHA256:
		return "SHA256"
	case SHA512:
		return "SHA512"
	default:
		return "SHA1"
	}
}

func HOTP(secret []byte, counter uint64, digits int, alg Algorithm) string {
	mac := hmac.New(alg.newHash(), secret)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac.Write(msg[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, code%mod)
}

func TOTP(secret []byte, t time.Time, period uint64, digits int, alg Algorithm) string {
	return HOTP(secret, uint64(t.Unix())/period, digits, alg)
}

// SecondsLeft is how long the current TOTP code stays valid.
func SecondsLeft(t time.Time, period uint64) int {
	return int(period - uint64(t.Unix())%period)
}
