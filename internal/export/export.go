// Package export writes accounts in formats password managers can import.
// All outputs are unencrypted.
package export

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"

	"github.com/rutvik24/otp-migration-helper/internal/account"
	"github.com/rutvik24/otp-migration-helper/internal/migration"
)

func title(a migration.Account) string {
	if a.Issuer != "" {
		return a.Issuer
	}
	return a.Name
}

type bitwardenLogin struct {
	Username string `json:"username"`
	Totp     string `json:"totp"`
}

type bitwardenItem struct {
	Type  int            `json:"type"`
	Name  string         `json:"name"`
	Login bitwardenLogin `json:"login"`
}

// Bitwarden returns Bitwarden's unencrypted JSON import format.
func Bitwarden(accts []migration.Account) ([]byte, error) {
	items := make([]bitwardenItem, len(accts))
	for i, a := range accts {
		items[i] = bitwardenItem{Type: 1, Name: title(a), Login: bitwardenLogin{Username: a.Name, Totp: account.URL(a)}}
	}
	doc := struct {
		Encrypted bool            `json:"encrypted"`
		Folders   []any           `json:"folders"`
		Items     []bitwardenItem `json:"items"`
	}{Folders: []any{}, Items: items}
	return json.MarshalIndent(doc, "", "  ")
}

// PasswordsCSV returns a CSV for the macOS Passwords app and other CSV importers.
func PasswordsCSV(accts []migration.Account) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write([]string{"Title", "URL", "Username", "Password", "Notes", "OTPAuth"}); err != nil {
		return nil, err
	}
	for _, a := range accts {
		if err := w.Write([]string{title(a), "", a.Name, "", "", account.URL(a)}); err != nil {
			return nil, err
		}
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

// OTPAuthList returns one otpauth:// URL per line.
func OTPAuthList(accts []migration.Account) []byte {
	urls := make([]string, len(accts))
	for i, a := range accts {
		urls[i] = account.URL(a)
	}
	return []byte(strings.Join(urls, "\n") + "\n")
}
