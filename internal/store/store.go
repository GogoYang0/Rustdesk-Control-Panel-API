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
		// 文件型 SQLite 必须在打开前确保父目录存在，否则建库直接失败
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

	// 单文件 SQLite 用单连接避免锁问题
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

	return &Store{DB: db}, nil
}

// applyDialTimeouts 为驱动 DSN 补充拨号/读写超时，限制 gorm.Open 初始化阶段的耗时。
// 必须按各自 DSN 格式精确插入参数，避免改写密码等含特殊字符的字段。
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
		// 键值风格 DSN：空格分隔，密码中的任何字符都不受影响
		return dsn + " connect_timeout=5"
	}
	return dsn
}

// mysqlParamsIndex 返回 MySQL DSN 参数区起始 '?' 的下标（无参数区返回 -1）。
// 与 go-sql-driver 的解析规则一致：在最后一个 '/' 之后从前往后找第一个 '?'，
// 因此密码（位于 '/' 之前）与参数值中的 '?' 都不会被误判。
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
	// 已有参数区：逐个按参数名补齐缺失项，已设置的不动（驱动后值覆盖前值）
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

// hasMySQLParam 报告参数区是否已包含指定参数名。
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
