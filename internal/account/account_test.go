package account

import (
	"strings"
	"testing"

	"github.com/rutvik24/otp-migration-helper/internal/migration"
	"github.com/rutvik24/otp-migration-helper/internal/otp"
)

func totp() migration.Account {
	return migration.Account{Name: "me@x.com", Issuer: "Acme", Secret: []byte("12345678901234567890"), Algorithm: otp.SHA256, Digits: 8, Kind: migration.TOTP}
}

func TestURL_Totp(t *testing.T) {
	want := "otpauth://totp/Acme:me@x.com?algorithm=SHA256&digits=8&issuer=Acme&period=30&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	if got := URL(totp()); got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestURL_HotpIncludesCounter(t *testing.T) {
	a := totp()
	a.Kind, a.Counter = migration.HOTP, 5
	got := URL(a)
	if !strings.HasPrefix(got, "otpauth://hotp/") || !strings.Contains(got, "counter=5") || strings.Contains(got, "period") {
		t.Errorf("unexpected %s", got)
	}
}

func TestURL_EscapesLabel(t *testing.T) {
	a := totp()
	a.Issuer, a.Name = "A:cme Ltd", "jöhn doe"
	got := URL(a)
	if !strings.HasPrefix(got, "otpauth://totp/A%3Acme%20Ltd:j%C3%B6hn%20doe?") {
		t.Errorf("label not escaped: %s", got)
	}
	a.Issuer = ""
	if got := URL(a); !strings.HasPrefix(got, "otpauth://totp/j%C3%B6hn%20doe?") || strings.Contains(got, "issuer=") {
		t.Errorf("empty issuer: %s", got)
	}
}

func TestBase32_NoPadding(t *testing.T) {
	if got := Base32([]byte("a")); got != "ME" {
		t.Errorf("got %s", got)
	}
}
