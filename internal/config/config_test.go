package config_test

import (
	"os"
	"path/filepath"
	"testing"

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
