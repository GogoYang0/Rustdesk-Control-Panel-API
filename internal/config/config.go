// Package config loads and validates process configuration.
package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config is the root configuration tree.
type Config struct {
	Server      ServerConfig      `mapstructure:"server"`
	Log         LogConfig         `mapstructure:"log"`
	Database    DatabaseConfig    `mapstructure:"database"`
	Auth        AuthConfig        `mapstructure:"auth"`
	Provision   ProvisionConfig   `mapstructure:"provision"`
	Mail        MailConfig        `mapstructure:"mail"`
	Web         WebConfig         `mapstructure:"web"`
	Compat      CompatConfig      `mapstructure:"compat"`
	Logcollect  LogcollectConfig  `mapstructure:"logcollect"`
	Session     SessionConfig     `mapstructure:"session"`
	Audit       AuditConfig       `mapstructure:"audit"`
	Captcha     CaptchaConfig     `mapstructure:"captcha"`
	ClientBuild ClientBuildConfig `mapstructure:"clientbuild"`
	WebAuthn    WebAuthnConfig    `mapstructure:"webauthn"`
	OIDC        OIDCConfig        `mapstructure:"oidc"`
	External    ExternalConfig    `mapstructure:"external"`
	LDAP        LDAPConfig        `mapstructure:"ldap"`
}

// CaptchaConfig enables the interactive captcha in front of the public
// credential-checking endpoints. Secrets (Altcha HMAC key, GeeTest key, Cap
// secret) are injected from the environment and never stored here.
type CaptchaConfig struct {
	Enabled      bool          `mapstructure:"enabled"`
	Provider     string        `mapstructure:"provider"`
	FailMode     string        `mapstructure:"failMode"`
	ChallengeTTL time.Duration `mapstructure:"challengeTTL"`
	Altcha       AltchaConfig  `mapstructure:"altcha"`
	Geetest      GeetestConfig `mapstructure:"geetest"`
	Cap          CapConfig     `mapstructure:"cap"`
}

// AltchaConfig tunes the built-in proof-of-work provider.
type AltchaConfig struct {
	MaxNumber int64  `mapstructure:"maxNumber"`
	Key       string `mapstructure:"key"`
}

// GeetestConfig tunes the GeeTest v4 provider.
type GeetestConfig struct {
	CaptchaID string `mapstructure:"captchaId"`
	Key       string `mapstructure:"key"`
}

// CapConfig tunes the self-hosted Cap provider.
type CapConfig struct {
	InstanceURL string `mapstructure:"instanceUrl"`
	SiteKey     string `mapstructure:"siteKey"`
	Secret      string `mapstructure:"secret"`
}

// AuditConfig tunes audit-log retention archiving.
type AuditConfig struct {
	// ArchiveDir receives per-organization JSONL archives before the source
	// rows are purged. It must live on storage included in operator backups.
	ArchiveDir string `mapstructure:"archiveDir"`
}

// SessionConfig tunes the session-governance background sweeps.
type SessionConfig struct {
	// IdleTimeout is how long an open session may go without activity
	// before the idle sweep closes it. Sessions with no recorded activity
	// fall back to their start time. Must be positive.
	IdleTimeout time.Duration `mapstructure:"idleTimeout"`
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
	// Zero disables retention cleanup entirely (no periodic sweep and no
	// startup sweep); any non-zero value must be at least one minute.
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
	// Captcha provider secrets follow the same policy: the tracked config file
	// carries non-secret parameters only.
	if err := v.BindEnv("captcha.altcha.key", "PANEL_CAPTCHA_ALTCHA_KEY"); err != nil {
		return nil, fmt.Errorf("bind captcha altcha key: %w", err)
	}
	if err := v.BindEnv("captcha.geetest.key", "PANEL_CAPTCHA_GEETEST_KEY"); err != nil {
		return nil, fmt.Errorf("bind captcha geetest key: %w", err)
	}
	if err := v.BindEnv("captcha.cap.secret", "PANEL_CAPTCHA_CAP_SECRET"); err != nil {
		return nil, fmt.Errorf("bind captcha cap secret: %w", err)
	}
	v.SetDefault("mail.devMode", true)
	v.SetDefault("mail.smtp.port", 587)
	v.SetDefault("compat.accessTTL", "720h")
	v.SetDefault("session.idleTimeout", "10m")
	v.SetDefault("audit.archiveDir", "./data/audit-archive")
	// Log collection is opt-in: without rules nothing can be parsed.
	v.SetDefault("logcollect.enabled", false)
	v.SetDefault("logcollect.containerprefix", "panel-org")
	v.SetDefault("logcollect.retentionsweepinterval", 6*time.Hour)
	// Captcha is opt-in; Altcha is the default provider because it needs no
	// external service.
	v.SetDefault("captcha.enabled", false)
	v.SetDefault("captcha.provider", "altcha")
	v.SetDefault("captcha.failmode", "closed")
	v.SetDefault("captcha.challengettl", 5*time.Minute)
	v.SetDefault("captcha.altcha.maxnumber", int64(100000))
	// Frontend origin for links inside outgoing emails.
	v.SetDefault("web.baseurl", "http://localhost:5173")
	if err := v.BindEnv("web.baseurl", "PANEL_WEB_BASE_URL"); err != nil {
		return nil, fmt.Errorf("bind web base url env: %w", err)
	}
	v.SetDefault("clientbuild.enabled", false)
	v.SetDefault("clientbuild.assetDir", "./data/client-builds")
	v.SetDefault("clientbuild.rustdeskVersion", "1.5.0")
	v.SetDefault("clientbuild.github.apiBaseURL", "https://api.github.com")
	v.SetDefault("clientbuild.github.workflow", "build-client.yml")
	v.SetDefault("clientbuild.github.ref", "main")
	v.SetDefault("clientbuild.github.artifactHosts", []string{"github.com", "*.githubusercontent.com", "*.blob.core.windows.net"})
	v.SetDefault("clientbuild.bundle.ttl", "24h")
	v.SetDefault("clientbuild.pollInterval", "30s")
	v.SetDefault("clientbuild.pendingTimeout", "12h")
	v.SetDefault("clientbuild.dispatchTimeout", "10m")
	v.SetDefault("clientbuild.buildTimeout", "3h")
	v.SetDefault("clientbuild.ingestTimeout", "1h")
	v.SetDefault("clientbuild.artifactRetention", "720h")
	v.SetDefault("clientbuild.deleteRemoteArtifacts", true)
	v.SetDefault("clientbuild.maxProfilesPerOrg", 10)
	v.SetDefault("clientbuild.maxConcurrentPerOrg", 2)
	v.SetDefault("clientbuild.maxActiveBuilds", 4)
	v.SetDefault("clientbuild.maxArtifactBytes", int64(2147483648))
	v.SetDefault("clientbuild.platforms", []string{"windows-x64", "linux-x64", "macos-arm64", "macos-x64", "android-arm64"})
	if err := v.BindEnv("clientbuild.github.token", "PANEL_CLIENTBUILD_GITHUB_TOKEN"); err != nil {
		return nil, fmt.Errorf("bind client build github token: %w", err)
	}
	if err := v.BindEnv("clientbuild.bundle.key", "PANEL_CLIENTBUILD_BUNDLE_KEY"); err != nil {
		return nil, fmt.Errorf("bind client build bundle key: %w", err)
	}
	// OIDC is opt-in and single-provider; its secret is environment-only.
	v.SetDefault("oidc.enabled", false)
	v.SetDefault("oidc.providername", defaultOIDCProviderName)
	v.SetDefault("oidc.scopes", []string{"openid", "profile", "email"})
	v.SetDefault("oidc.clockskew", defaultOIDCClockSkew)
	v.SetDefault("oidc.statettl", defaultOIDCStateTTL)
	v.SetDefault("external.requirelocalsecondfactor", false)
	v.SetDefault("ldap.enabled", false)
	v.SetDefault("ldap.providername", "Directory")
	v.SetDefault("ldap.port", 636)
	v.SetDefault("ldap.transport", "ldaps")
	v.SetDefault("ldap.scope", "sub")
	v.SetDefault("ldap.userfilter", "(objectClass=person)")
	v.SetDefault("ldap.usernameattribute", "uid")
	v.SetDefault("ldap.mailattribute", "mail")
	v.SetDefault("ldap.timeout", 10*time.Second)
	// Passkeys are opt-in; the RP identity is deployment-wide and has no secrets.
	v.SetDefault("webauthn.enabled", false)
	v.SetDefault("webauthn.rpName", defaultWebAuthnDisplayName)
	v.SetDefault("webauthn.ceremonyTTL", 5*time.Minute)
	v.SetDefault("webauthn.credentialsPerUser", 10)

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

	if err := validateClientBuild(cfg.ClientBuild); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}
	if err := validateWebAuthn(cfg.WebAuthn); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}
	// Read the client secret only from the environment: a value in the tracked
	// file would be a leaked credential (design O8).
	cfg.OIDC.ClientSecret = os.Getenv("PANEL_OIDC_CLIENT_SECRET")
	// Same rule for the LDAP service-account password (design L4).
	cfg.LDAP.BindPassword = os.Getenv("PANEL_LDAP_BIND_PASSWORD")
	// A leading or trailing space in the host passes the non-empty check but
	// fails every dial: trim before validation so the configured value is the
	// value that gets used.
	cfg.LDAP.Host = strings.TrimSpace(cfg.LDAP.Host)
	if err := validateOIDC(cfg.OIDC, cfg.Web.BaseURL); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}
	if err := validateLDAP(cfg.LDAP); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}
	if err := validateProviders(cfg.OIDC, cfg.LDAP); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}
	if err := validateLogcollect(cfg.Logcollect); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}
	if err := validateCaptcha(cfg.Captcha); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}

	return &cfg, nil
}

// validateCaptcha checks the structural captcha settings. Provider secrets are
// validated by the provider builder at startup so a deployment cannot boot
// with an enabled captcha that can never verify anything.
func validateCaptcha(cfg CaptchaConfig) error {
	switch cfg.Provider {
	case "altcha", "geetest", "cap":
	default:
		return fmt.Errorf("captcha.provider must be altcha, geetest or cap, got %q", cfg.Provider)
	}
	switch cfg.FailMode {
	case "closed", "open":
	default:
		return fmt.Errorf("captcha.failMode must be closed or open, got %q", cfg.FailMode)
	}
	if cfg.ChallengeTTL < time.Minute || cfg.ChallengeTTL > 10*time.Minute {
		return fmt.Errorf("captcha.challengeTTL must be between 1m and 10m, got %s", cfg.ChallengeTTL)
	}
	if cfg.Altcha.MaxNumber < 10000 || cfg.Altcha.MaxNumber > 5000000 {
		return fmt.Errorf("captcha.altcha.maxNumber must be between 10000 and 5000000, got %d", cfg.Altcha.MaxNumber)
	}
	if !cfg.Enabled {
		return nil
	}
	switch cfg.Provider {
	case "geetest":
		if strings.TrimSpace(cfg.Geetest.CaptchaID) == "" {
			return fmt.Errorf("captcha.geetest.captchaId is required when the geetest provider is enabled")
		}
	case "cap":
		u, err := url.Parse(strings.TrimSpace(cfg.Cap.InstanceURL))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("captcha.cap.instanceUrl must be an http(s) URL when the cap provider is enabled")
		}
		if strings.TrimSpace(cfg.Cap.SiteKey) == "" {
			return fmt.Errorf("captcha.cap.siteKey is required when the cap provider is enabled")
		}
	}
	return nil
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
