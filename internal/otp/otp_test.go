package otp

import (
	"testing"
	"time"
)

func TestHOTP_RFC4226(t *testing.T) {
	secret := []byte("12345678901234567890")
	cases := map[uint64]string{0: "755224", 1: "287082"}
	for counter, want := range cases {
		if got := HOTP(secret, counter, 6, SHA1); got != want {
			t.Errorf("HOTP counter %d = %s, want %s", counter, got, want)
		}
	}
}

func TestTOTP_RFC6238(t *testing.T) {
	at := time.Unix(59, 0)
	cases := []struct {
		name   string
		secret string
		alg    Algorithm
		want   string
	}{
		{"sha1", "12345678901234567890", SHA1, "94287082"},
		{"sha256", "12345678901234567890123456789012", SHA256, "46119246"},
		{"sha512", "1234567890123456789012345678901234567890123456789012345678901234", SHA512, "90693936"},
	}
	for _, c := range cases {
		if got := TOTP([]byte(c.secret), at, 30, 8, c.alg); got != c.want {
			t.Errorf("%s = %s, want %s", c.name, got, c.want)
		}
	}
}

func TestSecondsLeft(t *testing.T) {
	if got := SecondsLeft(time.Unix(59, 0), 30); got != 1 {
		t.Errorf("t=59: got %d, want 1", got)
	}
	if got := SecondsLeft(time.Unix(60, 0), 30); got != 30 {
		t.Errorf("t=60: got %d, want 30", got)
	}
}
