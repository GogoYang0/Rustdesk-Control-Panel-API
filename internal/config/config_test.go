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
