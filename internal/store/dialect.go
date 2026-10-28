package store

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib" // PostgreSQL driver, registered as "pgx"
	_ "modernc.org/sqlite"             // SQLite driver, registered as "sqlite"
)

// dialect holds everything that differs between the supported databases; the
// rest of the store is written once, with ? placeholders.
type dialect struct {
	name   string
	driver string
	// schema creates the tables, one statement each (MySQL cannot run several at once).
	schema []string
	// dollarPlaceholders turns ? into $1, $2, … (PostgreSQL).
	dollarPlaceholders bool
	// upsertWrapped stores the key-wrapping blob, replacing any previous one.
	upsertWrapped string
	// insertAccount adds an account and does nothing if its fingerprint exists.
	insertAccount string
	maxOpenConns  int
}

const accountColumns = `(fingerprint, issuer, name, kind, algorithm, digits, counter, secret) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

var sqliteDialect = dialect{
	name:   "SQLite",
	driver: "sqlite",
	schema: []string{
		`CREATE TABLE meta (k TEXT PRIMARY KEY, v BLOB NOT NULL)`,
		`CREATE TABLE accounts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			fingerprint TEXT NOT NULL UNIQUE,
			issuer TEXT NOT NULL,
			name TEXT NOT NULL,
			kind INTEGER NOT NULL,
			algorithm INTEGER NOT NULL,
			digits INTEGER NOT NULL,
			counter INTEGER NOT NULL,
			secret BLOB NOT NULL)`,
		`CREATE TABLE activity_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ts INTEGER NOT NULL,
			action TEXT NOT NULL,
			detail TEXT NOT NULL)`,
		`CREATE TABLE recovery_state (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			failures INTEGER NOT NULL,
			locked_until INTEGER NOT NULL)`,
		`INSERT INTO recovery_state (id, failures, locked_until) VALUES (1, 0, 0)`,
	},
	upsertWrapped: `INSERT INTO meta (k, v) VALUES ('wrapped', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v`,
	insertAccount: `INSERT INTO accounts ` + accountColumns + ` ON CONFLICT(fingerprint) DO NOTHING`,
	maxOpenConns:  1,
}

var postgresDialect = dialect{
	name:   "PostgreSQL",
	driver: "pgx",
	schema: []string{
		`CREATE TABLE meta (k VARCHAR(64) PRIMARY KEY, v BYTEA NOT NULL)`,
		`CREATE TABLE accounts (
			id BIGSERIAL PRIMARY KEY,
			fingerprint VARCHAR(64) NOT NULL UNIQUE,
			issuer TEXT NOT NULL,
			name TEXT NOT NULL,
			kind INTEGER NOT NULL,
			algorithm INTEGER NOT NULL,
			digits INTEGER NOT NULL,
			counter BIGINT NOT NULL,
			secret BYTEA NOT NULL)`,
		`CREATE TABLE activity_log (
			id BIGSERIAL PRIMARY KEY,
			ts BIGINT NOT NULL,
			action TEXT NOT NULL,
			detail TEXT NOT NULL)`,
		`CREATE TABLE recovery_state (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			failures INTEGER NOT NULL,
			locked_until BIGINT NOT NULL)`,
		`INSERT INTO recovery_state (id, failures, locked_until) VALUES (1, 0, 0)`,
	},
	dollarPlaceholders: true,
	upsertWrapped:      `INSERT INTO meta (k, v) VALUES ('wrapped', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v`,
	insertAccount:      `INSERT INTO accounts ` + accountColumns + ` ON CONFLICT(fingerprint) DO NOTHING`,
	maxOpenConns:       10,
}

const mysqlTable = ` ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`

var mysqlDialect = dialect{
	name:   "MySQL",
	driver: "mysql",
	schema: []string{
		`CREATE TABLE meta (k VARCHAR(64) NOT NULL PRIMARY KEY, v LONGBLOB NOT NULL)` + mysqlTable,
		`CREATE TABLE accounts (
			id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
			fingerprint VARCHAR(64) NOT NULL UNIQUE,
			issuer TEXT NOT NULL,
			name TEXT NOT NULL,
			kind INT NOT NULL,
			algorithm INT NOT NULL,
			digits INT NOT NULL,
			counter BIGINT NOT NULL,
			secret LONGBLOB NOT NULL)` + mysqlTable,
		`CREATE TABLE activity_log (
			id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
			ts BIGINT NOT NULL,
			action TEXT NOT NULL,
			detail TEXT NOT NULL)` + mysqlTable,
		`CREATE TABLE recovery_state (
			id INT NOT NULL PRIMARY KEY CHECK (id = 1),
			failures INT NOT NULL,
			locked_until BIGINT NOT NULL)` + mysqlTable,
		`INSERT INTO recovery_state (id, failures, locked_until) VALUES (1, 0, 0)`,
	},
	upsertWrapped: `INSERT INTO meta (k, v) VALUES ('wrapped', ?) ON DUPLICATE KEY UPDATE v = VALUES(v)`,
	// A no-op update, not INSERT IGNORE, so real errors are not swallowed.
	insertAccount: `INSERT INTO accounts ` + accountColumns + ` ON DUPLICATE KEY UPDATE id = id`,
	maxOpenConns:  10,
}

// IsDatabaseURL reports whether a vault target names a PostgreSQL or MySQL
// server (rather than a SQLite file path).
func IsDatabaseURL(target string) bool { return hasScheme(target) }

func hasScheme(target string) bool {
	for _, p := range []string{"postgres://", "postgresql://", "mysql://"} {
		if strings.HasPrefix(target, p) {
			return true
		}
	}
	return false
}

// resolve picks the dialect and driver connection string for a target: a
// postgres://, postgresql:// or mysql:// URL, or otherwise a SQLite file path.
func resolve(target string) (dialect, string, error) {
	switch {
	case strings.HasPrefix(target, "postgres://"), strings.HasPrefix(target, "postgresql://"):
		return postgresDialect, target, nil
	case strings.HasPrefix(target, "mysql://"):
		dsn, err := mysqlDSN(target)
		return mysqlDialect, dsn, err
	case target == "":
		return dialect{}, "", errors.New("no vault location given")
	}
	return sqliteDialect, target, nil
}

// mysqlDSN converts mysql://user:pass@host:port/db?tls=true into the go-sql-driver form.
func mysqlDSN(target string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", errors.New("the MySQL URL is not valid; use mysql://user:password@host:3306/database")
	}
	db := strings.TrimPrefix(u.Path, "/")
	if u.Host == "" || db == "" {
		return "", errors.New("the MySQL URL needs a host and a database name: mysql://user:password@host:3306/database")
	}
	cfg := mysql.NewConfig()
	cfg.User = u.User.Username()
	cfg.Passwd, _ = u.User.Password()
	cfg.Net = "tcp"
	cfg.Addr = u.Host
	if _, _, err := net.SplitHostPort(u.Host); err != nil {
		cfg.Addr = net.JoinHostPort(u.Hostname(), "3306")
	}
	cfg.DBName = db
	cfg.Params = map[string]string{"charset": "utf8mb4"}
	for key, values := range u.Query() {
		switch key {
		case "tls":
			cfg.TLSConfig = values[0]
		default:
			cfg.Params[key] = values[0]
		}
	}
	return cfg.FormatDSN(), nil
}

// Describe names a target for messages without ever including a password.
func Describe(target string) string {
	if !hasScheme(target) {
		return target
	}
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return "database"
	}
	kind := "MySQL"
	if strings.HasPrefix(u.Scheme, "postgres") {
		kind = "PostgreSQL"
	}
	return fmt.Sprintf("%s database %q on %s", kind, strings.TrimPrefix(u.Path, "/"), u.Host)
}

// DropForTests deletes every vault table in a PostgreSQL/MySQL test database
// so a test can start from empty. Never call it outside tests.
func DropForTests(target string) error {
	d, dsn, err := resolve(target)
	if err != nil {
		return err
	}
	db, err := connect(d, dsn)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	for _, table := range []string{"recovery_state", "activity_log", "accounts", "meta"} {
		if _, err := db.Exec("DROP TABLE IF EXISTS " + table); err != nil {
			return err
		}
	}
	return nil
}

// Exists reports whether a vault has been created at the target.
func Exists(target string) bool {
	d, dsn, err := resolve(target)
	if err != nil {
		return false
	}
	if d.driver == sqliteDialect.driver {
		_, err := os.Stat(target)
		return err == nil
	}
	db, err := connect(d, dsn)
	if err != nil {
		return false
	}
	defer func() { _ = db.Close() }()
	var n int
	return db.QueryRow(`SELECT COUNT(*) FROM meta WHERE k = 'wrapped'`).Scan(&n) == nil && n > 0
}

func connect(d dialect, dsn string) (*sql.DB, error) {
	db, err := sql.Open(d.driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("could not open the %s database: %w", d.name, err)
	}
	db.SetMaxOpenConns(d.maxOpenConns)
	db.SetConnMaxLifetime(3 * time.Minute)
	if d.driver != sqliteDialect.driver {
		if err := db.Ping(); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("could not connect to the %s database: %w", d.name, err)
		}
	}
	return db, nil
}

// rebind adapts ? placeholders to the dialect.
func (d dialect) rebind(query string) string {
	if !d.dollarPlaceholders {
		return query
	}
	var b strings.Builder
	n := 0
	for _, r := range query {
		if r == '?' {
			n++
			b.WriteString("$" + strconv.Itoa(n))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
