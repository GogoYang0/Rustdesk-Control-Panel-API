// Package config loads and validates process configuration.
package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

// Config is the root configuration tree.
type Config struct {
	Server     ServerConfig     `mapstructure:"server"`
	Log        LogConfig        `mapstructure:"log"`
	Database   DatabaseConfig   `mapstructure:"database"`
	Auth       AuthConfig       `mapstructure:"auth"`
	Provision  ProvisionConfig  `mapstructure:"provision"`
	Mail       MailConfig       `mapstructure:"mail"`
	Web        WebConfig        `mapstructure:"web"`
	Compat     CompatConfig     `mapstructure:"compat"`
	Logcollect LogcollectConfig `mapstructure:"logcollect"`
}

// LogcollectConfig tunes the hbbs/hbbr log collector. Rules are evaluated in
// order and the first match wins; lines that match no rule are counted and
// dropped (C7). Device association uses the named capture group "device"
// (the RustDesk id); every other named group lands in the event detail.
type LogcollectConfig struct {
	Enabled bool `mapstructure:"enabled"`
	// ContainerPrefix matches the provisioned container names
	// (panel-org-<orgID>-hbbs / -hbbr).
	ContainerPrefix string           `mapstructure:"containerPrefix"`
	Rules           []LogcollectRule `mapstructure:"rules"`
	// RetentionSweepInterval is the period of the log-event retention sweep.
	// Zero disables the periodic sweep (the startup pass still runs when the
	// collector is enabled).
	RetentionSweepInterval time.Duration `mapstructure:"retentionSweepInterval"`
}

// LogcollectRule is one configurable parsing rule.
type LogcollectRule struct {
	Name    string `mapstructure:"name"`
	Pattern string `mapstructure:"pattern"`
	Level   string `mapstructure:"level"`
	Kind    string `mapstructure:"kind"`
}

// CompatConfig tunes the RustDesk client compatibility endpoints. The
// access token is long-lived by design: desktop clients hold it until
// logout, and there is no refresh flow in the client protocol.
type CompatConfig struct {
	AccessTTL time.Duration `mapstructure:"accessTTL"`
}

// WebConfig points at the panel frontend so emails can link back to it.
type WebConfig struct {
	BaseURL string `mapstructure:"baseURL"`
}

// MailConfig selects the delivery backend. In devMode messages are written
// to stdout instead of being sent; otherwise SMTP settings apply and the
// password must come from PANEL_SMTP_PASSWORD (never from the tracked file).
type MailConfig struct {
	DevMode bool       `mapstructure:"devMode"`
	SMTP    SMTPConfig `mapstructure:"smtp"`
}

// SMTPConfig carries the SMTP server settings.
type SMTPConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Username string `mapstructure:"username"`
	From     string `mapstructure:"from"`
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

// ProvisionConfig holds hbbs/hbbr deployment settings.
type ProvisionConfig struct {
	PortStart      uint16 `mapstructure:"portStart"`
	PortEnd        uint16 `mapstructure:"portEnd"`
	OrgLabel       string `mapstructure:"orgLabel"`
	RoleLabel      string `mapstructure:"roleLabel"`
	RelayHost      string `mapstructure:"relayHost"`
	Image          string `mapstructure:"image"`
	DataDir        string `mapstructure:"dataDir"`
	MaxOrgsPerUser int    `mapstructure:"maxOrgsPerUser"`
	Workers        int    `mapstructure:"workers"`
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
	v.SetDefault("provision.portStart", 21116)
	v.SetDefault("provision.portEnd", 22115)
	v.SetDefault("provision.orgLabel", "com.rustdesk-panel.org")
	v.SetDefault("provision.roleLabel", "com.rustdesk-panel.role")
	v.SetDefault("provision.image", "")
	v.SetDefault("provision.dataDir", "./data/servergroups")
	v.SetDefault("provision.maxOrgsPerUser", 5)
	v.SetDefault("provision.workers", 2)

	// The signing key must not live in the repository; deployment supplies it.
	if err := v.BindEnv("auth.secret", "PANEL_AUTH_SECRET"); err != nil {
		return nil, fmt.Errorf("bind auth secret env: %w", err)
	}
	// Same policy for the SMTP password.
	if err := v.BindEnv("mail.smtp.password", "PANEL_SMTP_PASSWORD"); err != nil {
		return nil, fmt.Errorf("bind smtp password env: %w", err)
	}
	v.SetDefault("mail.devMode", true)
	v.SetDefault("mail.smtp.port", 587)
	v.SetDefault("compat.accessTTL", "720h")
	// Log collection is opt-in: without rules nothing can be parsed.
	v.SetDefault("logcollect.enabled", false)
	v.SetDefault("logcollect.containerprefix", "panel-org")
	v.SetDefault("logcollect.retentionsweepinterval", 6*time.Hour)
	// Frontend origin for links inside outgoing emails.
	v.SetDefault("web.baseurl", "http://localhost:5173")
	if err := v.BindEnv("web.baseurl", "PANEL_WEB_BASE_URL"); err != nil {
		return nil, fmt.Errorf("bind web base url env: %w", err)
	}

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

	if err := validateLogcollect(cfg.Logcollect); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}

	return &cfg, nil
}

// validateLogcollect rejects sweep intervals that would either hammer the
// database or silently masquerade as "disabled".
func validateLogcollect(cfg LogcollectConfig) error {
	v := cfg.RetentionSweepInterval
	// Zero disables the periodic sweep on purpose; anything between is a
	// misconfiguration (a 1s sweep scans the table every second).
	// Negative values are covered by the same bound: anything below a minute
	// that is not exactly zero is a misconfiguration.
	if v != 0 && v < time.Minute {
		return fmt.Errorf("logcollect.retentionSweepInterval must be 0 (disabled) or at least 1m, got %s", v)
	}
	return nil
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
