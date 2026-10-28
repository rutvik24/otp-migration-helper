// Package export writes accounts in formats password managers can import.
// All outputs are unencrypted.
package export

import (
	"bytes"
	"crypto/rand"
	"encoding/csv"
	"encoding/json"
	"fmt"
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

const defaultPeriod = 30

func kindName(a migration.Account) string {
	if a.Kind == migration.HOTP {
		return "hotp"
	}
	return "totp"
}

func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40 // version 4
	b[8] = b[8]&0x3f | 0x80 // variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

type aegisInfo struct {
	Secret  string  `json:"secret"`
	Algo    string  `json:"algo"`
	Digits  int     `json:"digits"`
	Period  int     `json:"period,omitempty"`
	Counter *uint64 `json:"counter,omitempty"`
}

type aegisEntry struct {
	Type     string    `json:"type"`
	UUID     string    `json:"uuid"`
	Name     string    `json:"name"`
	Issuer   string    `json:"issuer"`
	Note     string    `json:"note"`
	Favorite bool      `json:"favorite"`
	Icon     any       `json:"icon"`
	Info     aegisInfo `json:"info"`
	Groups   []string  `json:"groups"`
}

// Aegis returns Aegis Authenticator's plain (unencrypted) JSON export, which
// Aegis, Ente Auth, 2FAS and other apps can import.
func Aegis(accts []migration.Account) ([]byte, error) {
	entries := make([]aegisEntry, len(accts))
	for i, a := range accts {
		id, err := newUUID()
		if err != nil {
			return nil, err
		}
		info := aegisInfo{Secret: account.Base32(a.Secret), Algo: a.Algorithm.Name(), Digits: a.Digits}
		if a.Kind == migration.HOTP {
			counter := a.Counter
			info.Counter = &counter
		} else {
			info.Period = defaultPeriod
		}
		entries[i] = aegisEntry{Type: kindName(a), UUID: id, Name: a.Name, Issuer: a.Issuer, Info: info, Groups: []string{}}
	}
	doc := map[string]any{
		"version": 1,
		"header":  map[string]any{"slots": nil, "params": nil},
		"db":      map[string]any{"version": 3, "entries": entries, "groups": []any{}, "icons_optimized": true},
	}
	return json.MarshalIndent(doc, "", "  ")
}

type andOTPEntry struct {
	Secret        string   `json:"secret"`
	Issuer        string   `json:"issuer"`
	Label         string   `json:"label"`
	Digits        int      `json:"digits"`
	Type          string   `json:"type"`
	Algorithm     string   `json:"algorithm"`
	Thumbnail     string   `json:"thumbnail"`
	LastUsed      int64    `json:"last_used"`
	UsedFrequency int      `json:"used_frequency"`
	Period        int      `json:"period,omitempty"`
	Counter       *uint64  `json:"counter,omitempty"`
	Tags          []string `json:"tags"`
}

// AndOTP returns andOTP's plain (unencrypted) JSON backup format, which
// andOTP, Aegis and other apps can import.
func AndOTP(accts []migration.Account) ([]byte, error) {
	entries := make([]andOTPEntry, len(accts))
	for i, a := range accts {
		e := andOTPEntry{
			Secret: account.Base32(a.Secret), Issuer: a.Issuer, Label: a.Name, Digits: a.Digits,
			Type: strings.ToUpper(kindName(a)), Algorithm: a.Algorithm.Name(), Thumbnail: "Default", Tags: []string{},
		}
		if a.Kind == migration.HOTP {
			counter := a.Counter
			e.Counter = &counter
		} else {
			e.Period = defaultPeriod
		}
		entries[i] = e
	}
	return json.MarshalIndent(entries, "", "  ")
}
