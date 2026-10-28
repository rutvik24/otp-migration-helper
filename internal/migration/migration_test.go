package migration

import (
	"bytes"
	"encoding/base64"
	"net/url"
	"strconv"
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

func sampleAccounts() []Account {
	return []Account{
		{Name: "alice@acme.com", Issuer: "Acme", Secret: []byte("12345678901234567890"), Algorithm: otp.SHA1, Digits: 6, Kind: TOTP},
		{Name: "rutvik24", Issuer: "GitHub", Secret: []byte("secret-two-0123456789"), Algorithm: otp.SHA256, Digits: 8, Kind: TOTP},
		{Name: "AWS root", Secret: []byte("hotp-secret-bytes!!!"), Algorithm: otp.SHA512, Digits: 6, Kind: HOTP, Counter: 41},
		{Name: "jöhn \"d\" ☃", Issuer: "A:cme & Co", Secret: []byte{0x00, 0xff, 0x10, 0x80, 0x7f}, Algorithm: otp.SHA1, Digits: 6, Kind: TOTP},
	}
}

func TestEncode_RoundTripsThroughDecode(t *testing.T) {
	want := sampleAccounts()
	links, err := Encode(want, 10)
	if err != nil || len(links) != 1 {
		t.Fatalf("links=%d err=%v", len(links), err)
	}
	if !strings.HasPrefix(links[0], "otpauth-migration://offline?data=") {
		t.Errorf("not a Google Authenticator import link: %.60s", links[0])
	}
	batch, err := Decode(links[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Accounts) != len(want) || batch.Size != 1 || batch.Index != 0 {
		t.Fatalf("batch: %+v", batch)
	}
	for i, w := range want {
		g := batch.Accounts[i]
		if g.Name != w.Name || g.Issuer != w.Issuer || !bytes.Equal(g.Secret, w.Secret) || g.Algorithm != w.Algorithm || g.Digits != w.Digits || g.Kind != w.Kind || g.Counter != w.Counter {
			t.Errorf("account %d:\n got %+v\nwant %+v", i, g, w)
		}
	}
}

func TestEncode_SplitsIntoBatchesGoogleCanReassemble(t *testing.T) {
	var accts []Account
	for i := 0; i < 11; i++ {
		accts = append(accts, Account{Name: "user" + strconv.Itoa(i), Secret: []byte("12345678901234567890"), Digits: 6})
	}
	links, err := Encode(accts, 5)
	if err != nil || len(links) != 3 {
		t.Fatalf("11 accounts at 5 per code should make 3 codes: %d %v", len(links), err)
	}
	var ids = map[int32]bool{}
	total := 0
	for i, l := range links {
		b, err := Decode(l)
		if err != nil {
			t.Fatal(err)
		}
		if b.Size != 3 || b.Index != int32(i) {
			t.Errorf("code %d: size=%d index=%d", i, b.Size, b.Index)
		}
		ids[b.BatchID] = true
		total += len(b.Accounts)
	}
	if len(ids) != 1 || total != 11 {
		t.Errorf("every code must share one batch id and together hold every account: ids=%v total=%d", ids, total)
	}
}

func TestEncode_BatchIDsDifferBetweenExports(t *testing.T) {
	a, _ := Encode(sampleAccounts(), 10)
	b, _ := Encode(sampleAccounts(), 10)
	da, _ := Decode(a[0])
	db, _ := Decode(b[0])
	if da.BatchID == db.BatchID {
		t.Error("two exports should not share a batch id, or Google would merge them")
	}
}

func TestEncode_RejectsBadInput(t *testing.T) {
	if _, err := Encode(nil, 5); err == nil {
		t.Error("no accounts must be an error")
	}
	if _, err := Encode(sampleAccounts(), 0); err == nil {
		t.Error("zero per code must be an error")
	}
	if _, err := Encode([]Account{{Name: "x", Digits: 6}}, 5); err == nil {
		t.Error("an account without a secret must be an error")
	}
	if _, err := Encode([]Account{{Name: "x", Secret: []byte("s"), Digits: 7}}, 5); err == nil {
		t.Error("7 digits is not something Google can import")
	}
}
