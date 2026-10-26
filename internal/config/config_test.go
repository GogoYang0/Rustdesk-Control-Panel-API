package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
)

func TestLoad_ServerAddr(t *testing.T) {
	// The repository config intentionally ships no signing key; the deployment
	// injects it via PANEL_AUTH_SECRET.
	t.Setenv("PANEL_AUTH_SECRET", "test-secret-test-secret-test-secret")
	cfg, err := config.Load("../../configs/config.yaml")
	require.NoError(t, err)
	require.Equal(t, ":8080", cfg.Server.Addr)
	require.Equal(t, "info", cfg.Log.Level)
}

func TestLoad_EnvSecretOverridesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
server: {addr: ":8080"}
log: {level: info, format: json}
auth: {secret: "", accessTTL: 15m, refreshTTL: 168h}
`), 0o644))

	const envSecret = "env-secret-env-secret-env-secret-42"
	t.Setenv("PANEL_AUTH_SECRET", envSecret)
	cfg, err := config.Load(path)
	require.NoError(t, err)
	require.Equal(t, envSecret, cfg.Auth.Secret)
}

func TestLoad_RejectsWeakAuthSecret(t *testing.T) {
	// Neutralize an inherited PANEL_AUTH_SECRET (e.g. exported per the README
	// on a dev machine): viper prefers the environment over the file, and an
	// empty value is treated as unset, so the file's weak key is what gets
	// validated.
	t.Setenv("PANEL_AUTH_SECRET", "")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
server: {addr: ":8080"}
log: {level: info, format: json}
auth: {secret: "short", accessTTL: 15m, refreshTTL: 168h}
`), 0o644))

	_, err := config.Load(path)
	require.Error(t, err)
}

func TestLoad_RejectsPlaceholderSecret(t *testing.T) {
	// Same env isolation as the weak-secret test above.
	t.Setenv("PANEL_AUTH_SECRET", "")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
server: {addr: ":8080"}
log: {level: info, format: json}
auth: {secret: "dev-only-change-me", accessTTL: 15m, refreshTTL: 168h}
`), 0o644))

	_, err := config.Load(path)
	require.Error(t, err)
}

// The SMTP password must come only from PANEL_SMTP_PASSWORD; the tracked
// file cannot carry it (same policy as the JWT secret).
func TestLoad_SMTPPasswordFromEnvOnly(t *testing.T) {
	t.Setenv("PANEL_AUTH_SECRET", "test-signing-key-0123456789abcdef012345")
	t.Setenv("PANEL_SMTP_PASSWORD", "smtp-secret-123")

	cfg, err := config.Load("../../configs/config.yaml")
	require.NoError(t, err)
	require.True(t, cfg.Mail.DevMode, "default config ships with mail.devMode")
	require.Equal(t, 587, cfg.Mail.SMTP.Port)
}

func writeRetentionConfig(t *testing.T, dir, name, extra string) string {
	t.Helper()
	body := `server:
  addr: ":0"
auth:
  secret: "0123456789abcdef0123456789abcdef01234567"
  accessTTL: 15m
  refreshTTL: 168h
` + extra
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	return p
}

func TestLoad_RetentionSweepIntervalValidation(t *testing.T) {
	dir := t.TempDir()

	// Zero disables the periodic sweep on purpose.
	cfg, err := config.Load(writeRetentionConfig(t, dir, "disabled.yaml", `logcollect:
  retentionSweepInterval: 0
`))
	require.NoError(t, err)
	require.Zero(t, cfg.Logcollect.RetentionSweepInterval)

	// One minute is the documented minimum.
	cfg, err = config.Load(writeRetentionConfig(t, dir, "min.yaml", `logcollect:
  retentionSweepInterval: 1m
`))
	require.NoError(t, err)
	require.Equal(t, time.Minute, cfg.Logcollect.RetentionSweepInterval)

	// Sub-minute intervals would hammer the table.
	_, err = config.Load(writeRetentionConfig(t, dir, "too-fast.yaml", `logcollect:
  retentionSweepInterval: 30s
`))
	require.Error(t, err)
	require.Contains(t, err.Error(), "retentionSweepInterval")

	_, err = config.Load(writeRetentionConfig(t, dir, "negative.yaml", `logcollect:
  retentionSweepInterval: -5s
`))
	require.Error(t, err)
}

func TestLoad_RetentionSweepDefault(t *testing.T) {
	dir := t.TempDir()
	cfg, err := config.Load(writeRetentionConfig(t, dir, "default.yaml", ""))
	require.NoError(t, err)
	require.Equal(t, 6*time.Hour, cfg.Logcollect.RetentionSweepInterval)
}

// TestCaptchaConfigValidation exercises the captcha section through Load
// (this file is an external test package, so the unexported validator is
// out of reach). Secrets stay out of the file: the altcha/geetest/cap
// credentials are checked by the provider builder, not by config.Load.
func TestCaptchaConfigValidation(t *testing.T) {
	t.Setenv("PANEL_AUTH_SECRET", "test-secret-test-secret-test-secret")
	t.Setenv("PANEL_CAPTCHA_ALTCHA_KEY", "")
	t.Setenv("PANEL_CAPTCHA_GEETEST_KEY", "")
	t.Setenv("PANEL_CAPTCHA_CAP_SECRET", "")

	dir := t.TempDir()
	write := func(name, captcha string) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte(`
server: {addr: ":8080"}
auth: {secret: "", accessTTL: 15m, refreshTTL: 168h}
captcha:
`+captcha), 0o644))
		return path
	}

	t.Run("disabled defaults pass", func(t *testing.T) {
		cfg, err := config.Load(write("disabled.yaml", "  enabled: false\n"))
		require.NoError(t, err)
		require.False(t, cfg.Captcha.Enabled)
		require.Equal(t, "altcha", cfg.Captcha.Provider)
		require.Equal(t, "closed", cfg.Captcha.FailMode)
		require.Equal(t, 5*time.Minute, cfg.Captcha.ChallengeTTL)
		require.Equal(t, int64(100000), cfg.Captcha.Altcha.MaxNumber)
	})

	t.Run("unknown provider", func(t *testing.T) {
		_, err := config.Load(write("provider.yaml", "  enabled: true\n  provider: bogus\n"))
		require.ErrorContains(t, err, "captcha.provider")
	})

	t.Run("altcha without secret stays config-valid", func(t *testing.T) {
		// The HMAC key is a deployment secret: the provider builder rejects a
		// missing key at startup, config.Load only checks the structure.
		_, err := config.Load(write("altcha.yaml", "  enabled: true\n  provider: altcha\n"))
		require.NoError(t, err)
	})

	t.Run("geetest needs captchaId", func(t *testing.T) {
		_, err := config.Load(write("geetest.yaml", "  enabled: true\n  provider: geetest\n"))
		require.ErrorContains(t, err, "captcha.geetest.captchaId")
	})

	t.Run("cap needs http instance url", func(t *testing.T) {
		_, err := config.Load(write("cap.yaml", "  enabled: true\n  provider: cap\n  cap:\n    instanceUrl: \"ftp://cap\"\n    siteKey: site\n"))
		require.ErrorContains(t, err, "captcha.cap.instanceUrl")
	})

	t.Run("cap needs site key", func(t *testing.T) {
		_, err := config.Load(write("cap-site.yaml", "  enabled: true\n  provider: cap\n  cap:\n    instanceUrl: \"https://cap.example.com\"\n"))
		require.ErrorContains(t, err, "captcha.cap.siteKey")
	})

	t.Run("ttl out of range", func(t *testing.T) {
		_, err := config.Load(write("ttl.yaml", "  enabled: true\n  challengeTTL: 30s\n"))
		require.ErrorContains(t, err, "captcha.challengeTTL")
	})

	t.Run("fail mode enum", func(t *testing.T) {
		_, err := config.Load(write("failmode.yaml", "  enabled: true\n  failMode: maybe\n"))
		require.ErrorContains(t, err, "captcha.failMode")
	})

	t.Run("max number range", func(t *testing.T) {
		_, err := config.Load(write("maxnumber.yaml", "  enabled: true\n  altcha:\n    maxNumber: 1000\n"))
		require.ErrorContains(t, err, "captcha.altcha.maxNumber")
	})
}
