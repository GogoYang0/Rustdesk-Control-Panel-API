// Package store opens GORM database connections for the supported drivers.
package store

import (
	"context"
	"fmt"
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
func applyDialTimeouts(driver, dsn string) string {
	switch driver {
	case "postgres":
		if !strings.Contains(dsn, "connect_timeout") {
			if strings.Contains(dsn, "?") {
				dsn += "&connect_timeout=5"
			} else if strings.Contains(dsn, "=") {
				dsn += " connect_timeout=5"
			} else {
				dsn += "?connect_timeout=5"
			}
		}
	case "mysql":
		if !strings.Contains(dsn, "timeout=") {
			if strings.Contains(dsn, "?") {
				dsn += "&timeout=5s&readTimeout=10s&writeTimeout=10s"
			} else {
				dsn += "?timeout=5s&readTimeout=10s&writeTimeout=10s"
			}
		}
	}
	return dsn
}

func ensureDir(dsn string) error {
	p := strings.TrimPrefix(dsn, "file:")
	if dir := filepath.Dir(p); dir != "." && dir != "" {
		return os.MkdirAll(dir, 0o755)
	}
	return nil
}
