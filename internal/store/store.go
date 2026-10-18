// Package store opens GORM database connections for the supported drivers.
package store

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
)

// Store wraps the GORM database handle.
type Store struct {
	DB *gorm.DB
}

// Close releases the underlying database connections.
func (s *Store) Close() error {
	sqlDB, err := s.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// Open connects to the database described by cfg.
func Open(cfg config.DatabaseConfig) (*Store, error) {
	var dial gorm.Dialector

	switch cfg.Driver {
	case "sqlite":
		// File-backed SQLite needs its parent directory to exist before opening
		if !strings.Contains(cfg.DSN, ":memory:") {
			if err := ensureDir(cfg.DSN); err != nil {
				return nil, fmt.Errorf("prepare sqlite directory: %w", err)
			}
		}
		dial = sqlite.Open(cfg.DSN)
	case "postgres":
		dial = postgres.Open(applyDialTimeouts(cfg.Driver, cfg.DSN))
	case "mysql":
		dial = mysql.Open(applyDialTimeouts(cfg.Driver, cfg.DSN))
	default:
		return nil, fmt.Errorf("unsupported database driver %q", cfg.Driver)
	}

	db, err := gorm.Open(dial, &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("open %s database: %w", cfg.Driver, err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("wrap database handle: %w", err)
	}

	// A single connection avoids locking issues for file-backed SQLite
	if cfg.Driver == "sqlite" {
		sqlDB.SetMaxOpenConns(1)
	} else {
		sqlDB.SetMaxOpenConns(10)
		sqlDB.SetMaxIdleConns(2)
		sqlDB.SetConnMaxLifetime(time.Hour)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sqlDB.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping %s database: %w", cfg.Driver, err)
	}

	// Tenant scoping is enforced for every query on registered models.
	if err := registerTenantPlugin(db); err != nil {
		return nil, fmt.Errorf("register tenant plugin: %w", err)
	}

	return &Store{DB: db}, nil
}

// applyDialTimeouts appends dial/read/write timeouts to the driver DSN so that
// gorm.Open initialization cannot hang. Parameters must be inserted according to
// each DSN format so passwords and other special fields stay untouched.
func applyDialTimeouts(driver, dsn string) string {
	switch driver {
	case "postgres":
		return applyPostgresTimeouts(dsn)
	case "mysql":
		return applyMySQLTimeouts(dsn)
	}
	return dsn
}

func applyPostgresTimeouts(dsn string) string {
	if strings.Contains(dsn, "connect_timeout") {
		return dsn
	}
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			return dsn
		}
		q := u.Query()
		q.Set("connect_timeout", "5")
		u.RawQuery = q.Encode()
		return u.String()
	}
	if strings.Contains(dsn, "=") {
		// Keyword-value DSN: space-separated, so any character in the password is safe
		return dsn + " connect_timeout=5"
	}
	return dsn
}

// mysqlParamsIndex returns the index of the '?' that starts the params section of a
// MySQL DSN, or -1 when absent. It mirrors go-sql-driver: scan for the first '?'
// after the last '/', so neither passwords (before the '/') nor '?' inside param
// values are misdetected.
func mysqlParamsIndex(dsn string) int {
	slash := strings.LastIndex(dsn, "/")
	start := slash + 1
	if start >= len(dsn) {
		return -1
	}
	if i := strings.IndexByte(dsn[start:], '?'); i >= 0 {
		return start + i
	}
	return -1
}

func applyMySQLTimeouts(dsn string) string {
	if mysqlParamsIndex(dsn) < 0 {
		return dsn + "?timeout=5s&readTimeout=10s&writeTimeout=10s&parseTime=true"
	}
	// Existing params section: backfill missing params by name; set values stay as-is
	var b strings.Builder
	b.WriteString(dsn)
	for _, p := range []struct{ name, value string }{
		{"timeout", "timeout=5s"},
		{"readTimeout", "readTimeout=10s"},
		{"writeTimeout", "writeTimeout=10s"},
		{"parseTime", "parseTime=true"},
	} {
		if !hasMySQLParam(dsn, p.name) {
			b.WriteString("&" + p.value)
		}
	}
	return b.String()
}

// hasMySQLParam reports whether the params section already contains the named param.
func hasMySQLParam(dsn, name string) bool {
	idx := mysqlParamsIndex(dsn)
	if idx < 0 {
		return false
	}
	prefix := name + "="
	for _, kv := range strings.Split(dsn[idx+1:], "&") {
		if strings.HasPrefix(kv, prefix) {
			return true
		}
	}
	return false
}

func ensureDir(dsn string) error {
	p := strings.TrimPrefix(dsn, "file:")
	if dir := filepath.Dir(p); dir != "." && dir != "" {
		return os.MkdirAll(dir, 0o755)
	}
	return nil
}
