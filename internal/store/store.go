// Package store is the SQLite vault. Secrets are sealed with the data key;
// everything else (names, issuers, log) is plaintext.
package store

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	_ "modernc.org/sqlite"

	"github.com/rutvik24/otp-migration-helper/internal/migration"
	"github.com/rutvik24/otp-migration-helper/internal/otp"
	"github.com/rutvik24/otp-migration-helper/internal/vaultcrypto"
)

const (
	maxRecoveryFailures = 5
	recoveryLockout     = 24 * time.Hour
)

const schema = `
CREATE TABLE meta (k TEXT PRIMARY KEY, v BLOB NOT NULL);
CREATE TABLE accounts (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	fingerprint TEXT NOT NULL UNIQUE,
	issuer TEXT NOT NULL,
	name TEXT NOT NULL,
	kind INTEGER NOT NULL,
	algorithm INTEGER NOT NULL,
	digits INTEGER NOT NULL,
	counter INTEGER NOT NULL,
	secret BLOB NOT NULL
);
CREATE TABLE activity_log (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	ts INTEGER NOT NULL,
	action TEXT NOT NULL,
	detail TEXT NOT NULL
);
CREATE TABLE recovery_state (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	failures INTEGER NOT NULL,
	locked_until INTEGER NOT NULL
);
INSERT INTO recovery_state (id, failures, locked_until) VALUES (1, 0, 0);
`

type Store struct{ db *sql.DB }

type Record struct {
	ID int64
	migration.Account
}

type LogEntry struct {
	Time           time.Time
	Action, Detail string
}

// Create makes a new vault file (mode 0600); it fails if the file exists.
func Create(path string, w vaultcrypto.Wrapped) (*Store, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	s, err := open(path)
	if err != nil {
		return nil, err
	}
	if _, err := s.db.Exec(schema); err != nil {
		_ = s.Close()
		return nil, err
	}
	if err := s.SetWrapped(w); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

func Open(path string) (*Store, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	return open(path)
}

func open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Wrapped() (vaultcrypto.Wrapped, error) {
	var raw []byte
	if err := s.db.QueryRow(`SELECT v FROM meta WHERE k = 'wrapped'`).Scan(&raw); err != nil {
		return vaultcrypto.Wrapped{}, err
	}
	var w vaultcrypto.Wrapped
	return w, json.Unmarshal(raw, &w)
}

func (s *Store) SetWrapped(w vaultcrypto.Wrapped) error {
	raw, err := json.Marshal(w)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO meta (k, v) VALUES ('wrapped', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v`, raw)
	return err
}

// AddAccounts stores new accounts and returns how many were not already present.
func (s *Store) AddAccounts(key []byte, accts []migration.Account) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	added := 0
	for _, a := range accts {
		sealed, err := vaultcrypto.Seal(key, a.Secret)
		if err != nil {
			_ = tx.Rollback()
			return 0, err
		}
		res, err := tx.Exec(`INSERT INTO accounts (fingerprint, issuer, name, kind, algorithm, digits, counter, secret)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(fingerprint) DO NOTHING`,
			fingerprint(key, a), a.Issuer, a.Name, int(a.Kind), int(a.Algorithm), a.Digits, int64(a.Counter), sealed)
		if err != nil {
			_ = tx.Rollback()
			return 0, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			_ = tx.Rollback()
			return 0, err
		}
		added += int(n)
	}
	return added, tx.Commit()
}

func (s *Store) Accounts(key []byte) ([]Record, error) {
	rows, err := s.db.Query(`SELECT id, issuer, name, kind, algorithm, digits, counter, secret FROM accounts ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var recs []Record
	for rows.Next() {
		var r Record
		var kind, alg int
		var counter int64
		var sealed []byte
		if err := rows.Scan(&r.ID, &r.Issuer, &r.Name, &kind, &alg, &r.Digits, &counter, &sealed); err != nil {
			return nil, err
		}
		r.Kind, r.Algorithm, r.Counter = migration.Kind(kind), otp.Algorithm(alg), uint64(counter)
		if r.Secret, err = vaultcrypto.Open(key, sealed); err != nil {
			return nil, fmt.Errorf("account %d: %w", r.ID, err)
		}
		recs = append(recs, r)
	}
	return recs, rows.Err()
}

// Rekey re-encrypts every account under newKey and stores w, all in one
// transaction: either everything changes or nothing does.
func (s *Store) Rekey(oldKey, newKey []byte, w vaultcrypto.Wrapped) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if err := rekeyRows(tx, oldKey, newKey); err != nil {
		_ = tx.Rollback()
		return err
	}
	raw, err := json.Marshal(w)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`UPDATE meta SET v = ? WHERE k = 'wrapped'`, raw); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

type reseal struct {
	id          int64
	fingerprint string
	sealed      []byte
}

func rekeyRows(tx *sql.Tx, oldKey, newKey []byte) error {
	rows, err := tx.Query(`SELECT id, issuer, name, secret FROM accounts`)
	if err != nil {
		return err
	}
	var updates []reseal
	for rows.Next() {
		var id int64
		var a migration.Account
		var sealed []byte
		if err := rows.Scan(&id, &a.Issuer, &a.Name, &sealed); err != nil {
			_ = rows.Close()
			return err
		}
		if a.Secret, err = vaultcrypto.Open(oldKey, sealed); err != nil {
			_ = rows.Close()
			return fmt.Errorf("account %d: %w", id, err)
		}
		if sealed, err = vaultcrypto.Seal(newKey, a.Secret); err != nil {
			_ = rows.Close()
			return err
		}
		updates = append(updates, reseal{id, fingerprint(newKey, a), sealed})
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, u := range updates {
		if _, err := tx.Exec(`UPDATE accounts SET secret = ?, fingerprint = ? WHERE id = ?`, u.sealed, u.fingerprint, u.id); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) SetCounter(id int64, counter uint64) error {
	_, err := s.db.Exec(`UPDATE accounts SET counter = ? WHERE id = ?`, int64(counter), id)
	return err
}

func (s *Store) Log(action, detail string) error {
	_, err := s.db.Exec(`INSERT INTO activity_log (ts, action, detail) VALUES (?, ?, ?)`, time.Now().Unix(), action, detail)
	return err
}

func (s *Store) Logs() ([]LogEntry, error) {
	rows, err := s.db.Query(`SELECT ts, action, detail FROM activity_log ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var logs []LogEntry
	for rows.Next() {
		var ts int64
		var e LogEntry
		if err := rows.Scan(&ts, &e.Action, &e.Detail); err != nil {
			return nil, err
		}
		e.Time = time.Unix(ts, 0)
		logs = append(logs, e)
	}
	return logs, rows.Err()
}

func (s *Store) RecoveryState() (int, time.Time, error) {
	var failures int
	var until int64
	err := s.db.QueryRow(`SELECT failures, locked_until FROM recovery_state WHERE id = 1`).Scan(&failures, &until)
	return failures, time.Unix(until, 0), err
}

func (s *Store) RecordRecoveryFailure(now time.Time) error {
	failures, _, err := s.RecoveryState()
	if err != nil {
		return err
	}
	failures++
	var until int64
	if failures >= maxRecoveryFailures {
		until = now.Add(recoveryLockout).Unix()
	}
	_, err = s.db.Exec(`UPDATE recovery_state SET failures = ?, locked_until = ? WHERE id = 1`, failures, until)
	return err
}

func (s *Store) ClearRecoveryFailures() error {
	_, err := s.db.Exec(`UPDATE recovery_state SET failures = 0, locked_until = 0 WHERE id = 1`)
	return err
}

// fingerprint identifies an account for dedupe without revealing its secret.
func fingerprint(key []byte, a migration.Account) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(a.Issuer + "\x00" + a.Name + "\x00"))
	mac.Write(a.Secret)
	return hex.EncodeToString(mac.Sum(nil))
}
