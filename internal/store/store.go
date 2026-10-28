// Package store keeps the vault in SQLite, PostgreSQL or MySQL. Secrets are sealed with the data key;
// everything else (names, issuers, log) is plaintext.
package store

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/rutvik24/otp-migration-helper/internal/migration"
	"github.com/rutvik24/otp-migration-helper/internal/otp"
	"github.com/rutvik24/otp-migration-helper/internal/vaultcrypto"
)

const (
	maxRecoveryFailures = 5
	recoveryLockout     = 24 * time.Hour
)

// queryer is what both *sql.DB and *sql.Tx offer.
type queryer interface {
	Exec(query string, args ...any) (sql.Result, error)
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

// bound runs queries written with ? placeholders on the store's database.
type bound struct {
	q queryer
	d dialect
}

func (b bound) Exec(query string, args ...any) (sql.Result, error) {
	return b.q.Exec(b.d.rebind(query), args...)
}

func (b bound) Query(query string, args ...any) (*sql.Rows, error) {
	return b.q.Query(b.d.rebind(query), args...)
}

func (b bound) QueryRow(query string, args ...any) *sql.Row {
	return b.q.QueryRow(b.d.rebind(query), args...)
}

// txn is a transaction whose queries are rebound like the store's.
type txn struct {
	bound
	tx *sql.Tx
}

func (t *txn) Commit() error   { return t.tx.Commit() }
func (t *txn) Rollback() error { return t.tx.Rollback() }

// Store is the vault in a SQLite file, PostgreSQL or MySQL database.
type Store struct {
	db *sql.DB
	d  dialect
	bound
}

type Record struct {
	ID int64
	migration.Account
}

type LogEntry struct {
	Time           time.Time
	Action, Detail string
}

// Create makes a new vault at the target: a new SQLite file (mode 0600), or
// the tables in an empty PostgreSQL/MySQL database. It fails if a vault is
// already there.
func Create(target string, w vaultcrypto.Wrapped) (*Store, error) {
	d, dsn, err := resolve(target)
	if err != nil {
		return nil, err
	}
	if d.driver == sqliteDialect.driver {
		f, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, err
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
	} else if Exists(target) {
		return nil, errors.New("a vault already exists in this database")
	}

	s, err := open(d, dsn)
	if err != nil {
		return nil, err
	}
	for _, stmt := range d.schema {
		if _, err := s.db.Exec(stmt); err != nil {
			_ = s.Close()
			return nil, fmt.Errorf("could not create the vault tables: %w", err)
		}
	}
	if err := s.SetWrapped(w); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

// Open opens an existing vault at the target.
func Open(target string) (*Store, error) {
	d, dsn, err := resolve(target)
	if err != nil {
		return nil, err
	}
	if d.driver == sqliteDialect.driver {
		if _, err := os.Stat(target); err != nil {
			return nil, err
		}
	}
	s, err := open(d, dsn)
	if err != nil {
		return nil, err
	}
	if d.driver != sqliteDialect.driver {
		var n int
		if err := s.QueryRow(`SELECT COUNT(*) FROM meta WHERE k = 'wrapped'`).Scan(&n); err != nil || n == 0 {
			_ = s.Close()
			return nil, errors.New("no vault was found in this database; create one first")
		}
	}
	return s, nil
}

func open(d dialect, dsn string) (*Store, error) {
	db, err := connect(d, dsn)
	if err != nil {
		return nil, err
	}
	return &Store{db: db, d: d, bound: bound{q: db, d: d}}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) begin() (*txn, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	return &txn{bound: bound{q: tx, d: s.d}, tx: tx}, nil
}

func (s *Store) Wrapped() (vaultcrypto.Wrapped, error) {
	var raw []byte
	if err := s.QueryRow(`SELECT v FROM meta WHERE k = 'wrapped'`).Scan(&raw); err != nil {
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
	_, err = s.Exec(s.d.upsertWrapped, raw)
	return err
}

// AddAccounts stores new accounts and returns how many were not already present.
func (s *Store) AddAccounts(key []byte, accts []migration.Account) (int, error) {
	tx, err := s.begin()
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
		res, err := tx.Exec(s.d.insertAccount,
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
	rows, err := s.Query(`SELECT id, issuer, name, kind, algorithm, digits, counter, secret FROM accounts ORDER BY id`)
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
	tx, err := s.begin()
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

func rekeyRows(tx *txn, oldKey, newKey []byte) error {
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
	_, err := s.Exec(`UPDATE accounts SET counter = ? WHERE id = ?`, int64(counter), id)
	return err
}

func (s *Store) Log(action, detail string) error {
	_, err := s.Exec(`INSERT INTO activity_log (ts, action, detail) VALUES (?, ?, ?)`, time.Now().Unix(), action, detail)
	return err
}

func (s *Store) Logs() ([]LogEntry, error) {
	rows, err := s.Query(`SELECT ts, action, detail FROM activity_log ORDER BY id`)
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
	err := s.QueryRow(`SELECT failures, locked_until FROM recovery_state WHERE id = 1`).Scan(&failures, &until)
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
	_, err = s.Exec(`UPDATE recovery_state SET failures = ?, locked_until = ? WHERE id = 1`, failures, until)
	return err
}

func (s *Store) ClearRecoveryFailures() error {
	_, err := s.Exec(`UPDATE recovery_state SET failures = 0, locked_until = 0 WHERE id = 1`)
	return err
}

// fingerprint identifies an account for dedupe without revealing its secret.
func fingerprint(key []byte, a migration.Account) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(a.Issuer + "\x00" + a.Name + "\x00"))
	mac.Write(a.Secret)
	return hex.EncodeToString(mac.Sum(nil))
}
