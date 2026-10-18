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

func applyMySQLTimeouts(dsn string) string {
	if strings.Contains(dsn, "timeout=") {
		return dsn
	}
	// go-sql-driver 以最后一个 '?' 之后的部分为参数区，且仅当该 '?' 在
	// 地址段（最后一个 '/'）之后时才是参数分隔符；密码中的 '?' 位于 '/' 之前
	slash := strings.LastIndex(dsn, "/")
	qmark := strings.LastIndex(dsn, "?")
	if qmark > slash {
		return dsn + "&timeout=5s&readTimeout=10s&writeTimeout=10s"
	}
	return dsn + "?timeout=5s&readTimeout=10s&writeTimeout=10s"
}

func ensureDir(dsn string) error {
	p := strings.TrimPrefix(dsn, "file:")
	if dir := filepath.Dir(p); dir != "." && dir != "" {
		return os.MkdirAll(dir, 0o755)
	}
	return nil
}
