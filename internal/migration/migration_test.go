package migration

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"github.com/rutvik24/otp-migration-helper/internal/otp"
	"google.golang.org/protobuf/encoding/protowire"
)

type params struct {
	secret          []byte
	name, issuer    string
	alg, digits, ty int
	counter         int64
}

func encodeParams(p params) []byte {
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.BytesType)
	b = protowire.AppendBytes(b, p.secret)
	b = protowire.AppendTag(b, 2, protowire.BytesType)
	b = protowire.AppendString(b, p.name)
	b = protowire.AppendTag(b, 3, protowire.BytesType)
	b = protowire.AppendString(b, p.issuer)
	for i, v := range []int{p.alg, p.digits, p.ty} {
		b = protowire.AppendTag(b, protowire.Number(4+i), protowire.VarintType)
		b = protowire.AppendVarint(b, uint64(v))
	}
	b = protowire.AppendTag(b, 7, protowire.VarintType)
	return protowire.AppendVarint(b, uint64(p.counter))
}

func link(batchID, size, index int, ps ...params) string {
	var b []byte
	for _, p := range ps {
		b = protowire.AppendTag(b, 1, protowire.BytesType)
		b = protowire.AppendBytes(b, encodeParams(p))
	}
	for i, v := range []int{size, index, batchID} {
		b = protowire.AppendTag(b, protowire.Number(3+i), protowire.VarintType)
		b = protowire.AppendVarint(b, uint64(v))
	}
	return "otpauth-migration://offline?data=" + url.QueryEscape(base64.StdEncoding.EncodeToString(b))
}

func TestDecode_TotpAccount(t *testing.T) {
	l := link(7, 1, 0, params{secret: []byte("12345678901234567890"), name: "me@x.com", issuer: "Acme", alg: 2, digits: 2, ty: 2})
	batch, err := Decode(l)
	if err != nil {
		t.Fatal(err)
	}
	a := batch.Accounts[0]
	if a.Name != "me@x.com" || a.Issuer != "Acme" || a.Algorithm != otp.SHA256 || a.Digits != 8 || a.Kind != TOTP {
		t.Errorf("unexpected account %+v", a)
	}
	if batch.BatchID != 7 || batch.Size != 1 || batch.Index != 0 {
		t.Errorf("unexpected batch %+v", batch)
	}
}

func TestDecode_HotpCounter(t *testing.T) {
	batch, err := Decode(link(1, 1, 0, params{secret: []byte("s"), name: "n", ty: 1, counter: 42}))
	if err != nil {
		t.Fatal(err)
	}
	if a := batch.Accounts[0]; a.Kind != HOTP || a.Counter != 42 {
		t.Errorf("unexpected account %+v", a)
	}
}

func TestDecode_DefaultsWhenUnspecified(t *testing.T) {
	batch, err := Decode(link(1, 1, 0, params{secret: []byte("s"), name: "n", ty: 2}))
	if err != nil {
		t.Fatal(err)
	}
	if a := batch.Accounts[0]; a.Algorithm != otp.SHA1 || a.Digits != 6 {
		t.Errorf("unexpected defaults %+v", a)
	}
}

func TestDecode_PlusAsSpace(t *testing.T) {
	// Secret bytes chosen so the base64 text contains '+'.
	l := link(1, 1, 0, params{secret: []byte{0xfb, 0xef, 0xbe, 0xfb, 0xef}, name: "n", ty: 2})
	l = strings.ReplaceAll(l, "%2B", " ")
	if _, err := Decode(l); err != nil {
		t.Fatal(err)
	}
}

func TestDecode_Errors(t *testing.T) {
	good := link(1, 1, 0, params{secret: []byte("s"), name: "n", ty: 2})
	cases := map[string]string{
		"wrong scheme": "https://example.com",
		"empty data":   "otpauth-migration://offline?data=",
		"bad base64":   "otpauth-migration://offline?data=!!!",
		"truncated":    good[:len(good)-12],
	}
	for name, l := range cases {
		if _, err := Decode(l); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestDecodeURI_Totp(t *testing.T) {
	a, err := DecodeURI("otpauth://totp/Acme:me@x.com?secret=gezdgnbvgy3tqojqgezdgnbvgy3tqojq&issuer=Acme&algorithm=SHA256&digits=8&period=30")
	if err != nil {
		t.Fatal(err)
	}
	if a.Issuer != "Acme" || a.Name != "me@x.com" || a.Kind != TOTP || a.Algorithm != otp.SHA256 || a.Digits != 8 || string(a.Secret) != "12345678901234567890" {
		t.Errorf("unexpected %+v", a)
	}
}

func TestDecodeURI_HotpCounterAndDefaults(t *testing.T) {
	a, err := DecodeURI("otpauth://hotp/me?secret=GEZDGNBVGY3TQOJQ====&counter=7")
	if err != nil {
		t.Fatal(err)
	}
	if a.Kind != HOTP || a.Counter != 7 || a.Name != "me" || a.Issuer != "" || a.Algorithm != otp.SHA1 || a.Digits != 6 {
		t.Errorf("unexpected %+v", a)
	}
}

func TestDecodeURI_IssuerFromLabelEscapedAndSpaced(t *testing.T) {
	a, err := DecodeURI("otpauth://totp/A%3Acme%20Ltd:j%C3%B6hn%20doe?secret=GEZDGNBV%20GY3TQOJQ")
	if err != nil {
		t.Fatal(err)
	}
	if a.Name != "jöhn doe" || a.Issuer != "A:cme Ltd" {
		t.Errorf("unexpected %+v", a)
	}
}

func TestDecodeURI_Errors(t *testing.T) {
	cases := map[string]string{
		"wrong scheme":       "https://example.com",
		"unknown type":       "otpauth://steam/x?secret=GEZDGNBVGY3TQOJQ",
		"missing secret":     "otpauth://totp/x",
		"bad secret":         "otpauth://totp/x?secret=!!!!",
		"unsupported period": "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&period=60",
		"unsupported digits": "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&digits=7",
		"unsupported algo":   "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&algorithm=MD5",
		"bad counter":        "otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQ&counter=abc",
	}
	for name, l := range cases {
		if _, err := DecodeURI(l); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
