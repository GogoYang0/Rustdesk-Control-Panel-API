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

// Open connects to the database described by cfg.
func Open(cfg config.DatabaseConfig) (*Store, error) {
	var dial gorm.Dialector

	switch cfg.Driver {
	case "sqlite":
		dial = sqlite.Open(cfg.DSN)
	case "postgres":
		dial = postgres.Open(cfg.DSN)
	case "mysql":
		dial = mysql.Open(cfg.DSN)
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

	// 单文件 SQLite 用单连接避免锁问题；内存库跳过目录创建
	if cfg.Driver == "sqlite" {
		sqlDB.SetMaxOpenConns(1)
		if !strings.Contains(cfg.DSN, ":memory:") {
			ensureDir(cfg.DSN)
		}
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

func ensureDir(dsn string) {
	p := strings.TrimPrefix(dsn, "file:")
	if dir := filepath.Dir(p); dir != "." && dir != "" {
		_ = os.MkdirAll(dir, 0o755)
	}
}
