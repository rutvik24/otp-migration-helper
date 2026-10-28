package export

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rutvik24/otp-migration-helper/internal/account"
	"github.com/rutvik24/otp-migration-helper/internal/migration"
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
