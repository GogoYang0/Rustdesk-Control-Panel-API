// Package config loads and validates process configuration.
package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

// Config is the root configuration tree.
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Log      LogConfig      `mapstructure:"log"`
	Database DatabaseConfig `mapstructure:"database"`
	Auth     AuthConfig     `mapstructure:"auth"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Addr string `mapstructure:"addr"`
}

// LogConfig holds logger settings.
type LogConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
}

// AuthConfig holds JWT and token lifetime settings.
type AuthConfig struct {
	Secret     string        `mapstructure:"secret"`
	AccessTTL  time.Duration `mapstructure:"accessTTL"`
	RefreshTTL time.Duration `mapstructure:"refreshTTL"`
}

// DatabaseConfig holds database connection settings.
type DatabaseConfig struct {
	Driver string `mapstructure:"driver"` // sqlite | postgres | mysql
	DSN    string `mapstructure:"dsn"`
}

// Load reads configuration from the given YAML file.
func Load(path string) (*Config, error) {
	v := viper.New()
	v.SetConfigFile(path)
	v.SetDefault("database.driver", "sqlite")
	// cache=shared: all pooled database/sql connections share one in-memory database
	v.SetDefault("database.dsn", "file::memory:?cache=shared")
	v.SetDefault("auth.accessTTL", "15m")
	v.SetDefault("auth.refreshTTL", "168h")

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	if err := validateAuth(
		v.GetString("auth.secret"),
		v.GetDuration("auth.accessTTL"),
		v.GetDuration("auth.refreshTTL"),
	); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config %s: %w", path, err)
	}

	return &cfg, nil
}

// devSecretPlaceholder is rejected so a shipped config cannot become production.
const devSecretPlaceholder = "dev-only-change-me"

// validateAuth refuses secrets that would make token signatures predictable.
func validateAuth(secret string, accessTTL, refreshTTL time.Duration) error {
	if secret == "" {
		return fmt.Errorf("auth.secret must be configured")
	}
	if secret == devSecretPlaceholder {
		return fmt.Errorf("auth.secret still uses the development placeholder")
	}
	if len(secret) < 32 {
		return fmt.Errorf("auth.secret must be at least 32 bytes")
	}
	if accessTTL <= 0 || refreshTTL <= 0 {
		return fmt.Errorf("auth token lifetimes must be positive")
	}
	return nil
}
