package export

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/rutvik24/otp-migration-helper/internal/account"
	"github.com/rutvik24/otp-migration-helper/internal/migration"
	"github.com/rutvik24/otp-migration-helper/internal/otp"
)

func accounts() []migration.Account {
	return []migration.Account{
		{Name: "me@x.com", Issuer: "Acme", Secret: []byte("12345678901234567890"), Digits: 6, Kind: migration.TOTP},
		{Name: "no issuer", Secret: []byte("12345678901234567890"), Digits: 6, Kind: migration.TOTP},
	}
}

func TestBitwarden_Shape(t *testing.T) {
	data, err := Bitwarden(accounts())
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Encrypted bool  `json:"encrypted"`
		Folders   []any `json:"folders"`
		Items     []struct {
			Type  int    `json:"type"`
			Name  string `json:"name"`
			Login struct {
				Username string `json:"username"`
				Totp     string `json:"totp"`
			} `json:"login"`
		} `json:"items"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Encrypted || doc.Folders == nil || len(doc.Items) != 2 {
		t.Fatalf("doc: %+v", doc)
	}
	first, second := doc.Items[0], doc.Items[1]
	if first.Type != 1 || first.Name != "Acme" || first.Login.Username != "me@x.com" || first.Login.Totp != account.URL(accounts()[0]) {
		t.Errorf("first: %+v", first)
	}
	if second.Name != "no issuer" {
		t.Errorf("second name %q", second.Name)
	}
}

func TestPasswordsCSV_EscapesCommasQuotesNewlines(t *testing.T) {
	accts := []migration.Account{{Name: "a,b \"q\"\nline", Issuer: "Ac,me", Secret: []byte("s"), Digits: 6}}
	data, err := PasswordsCSV(accts)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	if strings.Join(rows[0], ",") != "Title,URL,Username,Password,Notes,OTPAuth" {
		t.Errorf("header %v", rows[0])
	}
	if rows[1][0] != "Ac,me" || rows[1][2] != "a,b \"q\"\nline" || rows[1][5] != account.URL(accts[0]) {
		t.Errorf("row %q", rows[1])
	}
}

func TestOTPAuthList(t *testing.T) {
	lines := strings.Split(strings.TrimSpace(string(OTPAuthList(accounts()))), "\n")
	if len(lines) != 2 || lines[0] != account.URL(accounts()[0]) {
		t.Errorf("lines: %v", lines)
	}
}

func mixedAccounts() []migration.Account {
	return []migration.Account{
		{Name: "me@x.com", Issuer: "Acme", Secret: []byte("12345678901234567890"), Algorithm: otp.SHA256, Digits: 8, Kind: migration.TOTP},
		{Name: "no issuer", Secret: []byte("12345678901234567890"), Algorithm: otp.SHA512, Digits: 6, Kind: migration.HOTP, Counter: 7},
	}
}

func TestAegis_Shape(t *testing.T) {
	data, err := Aegis(mixedAccounts())
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version int `json:"version"`
		Header  struct {
			Slots  any `json:"slots"`
			Params any `json:"params"`
		} `json:"header"`
		DB struct {
			Version int `json:"version"`
			Entries []struct {
				Type   string   `json:"type"`
				UUID   string   `json:"uuid"`
				Name   string   `json:"name"`
				Issuer string   `json:"issuer"`
				Groups []string `json:"groups"`
				Info   struct {
					Secret  string  `json:"secret"`
					Algo    string  `json:"algo"`
					Digits  int     `json:"digits"`
					Period  int     `json:"period"`
					Counter *uint64 `json:"counter"`
				} `json:"info"`
			} `json:"entries"`
			Groups []any `json:"groups"`
		} `json:"db"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != 1 || doc.Header.Slots != nil || doc.Header.Params != nil || doc.DB.Version != 3 || doc.DB.Groups == nil || len(doc.DB.Entries) != 2 {
		t.Fatalf("envelope: %+v", doc)
	}
	totp, hotp := doc.DB.Entries[0], doc.DB.Entries[1]
	if totp.Type != "totp" || totp.Name != "me@x.com" || totp.Issuer != "Acme" || totp.Info.Secret != "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" ||
		totp.Info.Algo != "SHA256" || totp.Info.Digits != 8 || totp.Info.Period != 30 || totp.Info.Counter != nil {
		t.Errorf("totp: %+v", totp)
	}
	if hotp.Type != "hotp" || hotp.Info.Algo != "SHA512" || hotp.Info.Counter == nil || *hotp.Info.Counter != 7 || hotp.Info.Period != 0 {
		t.Errorf("hotp: %+v", hotp)
	}
	uuid := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !uuid.MatchString(totp.UUID) || !uuid.MatchString(hotp.UUID) || totp.UUID == hotp.UUID || totp.Groups == nil {
		t.Errorf("uuids/groups: %q %q", totp.UUID, hotp.UUID)
	}
}

func TestAndOTP_Shape(t *testing.T) {
	data, err := AndOTP(mixedAccounts())
	if err != nil {
		t.Fatal(err)
	}
	var list []map[string]any
	if err := json.Unmarshal(data, &list); err != nil || len(list) != 2 {
		t.Fatalf("list=%v err=%v", list, err)
	}
	a, b := list[0], list[1]
	if a["type"] != "TOTP" || a["secret"] != "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" || a["issuer"] != "Acme" || a["label"] != "me@x.com" ||
		a["algorithm"] != "SHA256" || a["digits"] != float64(8) || a["period"] != float64(30) || a["tags"] == nil {
		t.Errorf("totp: %v", a)
	}
	if b["type"] != "HOTP" || b["counter"] != float64(7) || b["issuer"] != "" {
		t.Errorf("hotp: %v", b)
	}
	if _, has := a["counter"]; has {
		t.Error("a time-based entry has no counter")
	}
}
