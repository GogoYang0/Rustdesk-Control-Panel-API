package config_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
)

func TestLoad_ClientBuildDefaults(t *testing.T) {
	t.Setenv("PANEL_AUTH_SECRET", "test-secret-test-secret-test-secret")
	t.Setenv("PANEL_CLIENTBUILD_GITHUB_TOKEN", "")
	t.Setenv("PANEL_CLIENTBUILD_BUNDLE_KEY", "")

	cfg, err := config.Load("../../configs/config.yaml")
	require.NoError(t, err)
	require.False(t, cfg.ClientBuild.Enabled)
	require.Equal(t, "./data/client-builds", cfg.ClientBuild.AssetDir)
	require.Equal(t, "1.5.0", cfg.ClientBuild.RustdeskVersion)
	require.Equal(t, 30*time.Second, cfg.ClientBuild.PollInterval)
	require.Equal(t, 12*time.Hour, cfg.ClientBuild.PendingTimeout)
	require.Equal(t, 10*time.Minute, cfg.ClientBuild.DispatchTimeout)
	require.Equal(t, 3*time.Hour, cfg.ClientBuild.BuildTimeout)
	require.Equal(t, time.Hour, cfg.ClientBuild.IngestTimeout)
	require.Equal(t, 720*time.Hour, cfg.ClientBuild.ArtifactRetention)
	require.Equal(t, 24*time.Hour, cfg.ClientBuild.Bundle.TTL)
	require.Equal(t, int64(2147483648), cfg.ClientBuild.MaxArtifactBytes)
	require.ElementsMatch(t,
		[]string{"windows-x64", "linux-x64", "macos-arm64", "macos-x64", "android-arm64"},
		cfg.ClientBuild.Platforms)
}

func TestLoad_ClientBuildSecretsFromEnvOnly(t *testing.T) {
	t.Setenv("PANEL_AUTH_SECRET", "test-secret-test-secret-test-secret")
	t.Setenv("PANEL_CLIENTBUILD_GITHUB_TOKEN", "env-token")
	t.Setenv("PANEL_CLIENTBUILD_BUNDLE_KEY", "0123456789abcdef0123456789abcdef")

	path := writeConfig(t, `
clientbuild:
  enabled: false
  github:
    token: "file-token"
  bundle:
    key: "file-key-file-key-file-key-file-key"
`)
	cfg, err := config.Load(path)
	require.NoError(t, err)
	require.Equal(t, "env-token", cfg.ClientBuild.GitHub.Token)
	require.Equal(t, "0123456789abcdef0123456789abcdef", cfg.ClientBuild.Bundle.Key)
}

type clientBuildYAML struct {
	enabled       bool
	publicBaseURL string
	repo          string
	token         string
	bundleKey     string
	retention     string
	platforms     string
}

func (c clientBuildYAML) String() string {
	return fmt.Sprintf(`
clientbuild:
  enabled: %t
  publicBaseURL: "%s"
  assetDir: "./data/client-builds"
  rustdeskVersion: "1.5.0"
  github:
    apiBaseURL: https://api.github.com
    repo: "%s"
    workflow: build-client.yml
    ref: main
    token: "%s"
    artifactHosts: [github.com]
  bundle:
    ttl: 24h
    key: "%s"
  pollInterval: 30s
  pendingTimeout: 12h
  dispatchTimeout: 10m
  buildTimeout: 3h
  ingestTimeout: 1h
  artifactRetention: %s
  deleteRemoteArtifacts: true
  maxProfilesPerOrg: 10
  maxConcurrentPerOrg: 2
  maxActiveBuilds: 4
  maxArtifactBytes: 2147483648
  platforms: %s
`, c.enabled, c.publicBaseURL, c.repo, c.token, c.bundleKey, c.retention, c.platforms)
}

func TestLoad_ClientBuildEnabledValidation(t *testing.T) {
	t.Setenv("PANEL_AUTH_SECRET", "")
	t.Setenv("PANEL_CLIENTBUILD_GITHUB_TOKEN", "")
	t.Setenv("PANEL_CLIENTBUILD_BUNDLE_KEY", "")

	valid := clientBuildYAML{
		enabled:       true,
		publicBaseURL: "https://panel.example.com",
		repo:          "acme/build",
		token:         "pat",
		bundleKey:     "0123456789abcdef0123456789abcdef",
		retention:     "720h",
		platforms:     "[windows-x64, linux-x64]",
	}
	cases := []struct {
		name    string
		mutate  func(*clientBuildYAML)
		wantErr bool
	}{
		{"valid", func(*clientBuildYAML) {}, false},
		{"disabled may omit secrets", func(c *clientBuildYAML) {
			c.enabled = false
			c.publicBaseURL = ""
			c.repo = ""
			c.token = ""
			c.bundleKey = ""
		}, false},
		{"missing public base url", func(c *clientBuildYAML) { c.publicBaseURL = "" }, true},
		{"public base url with path", func(c *clientBuildYAML) { c.publicBaseURL = "https://panel.example.com/foo" }, true},
		{"missing repo", func(c *clientBuildYAML) { c.repo = "" }, true},
		{"invalid repo", func(c *clientBuildYAML) { c.repo = "not-a-repo" }, true},
		{"missing token", func(c *clientBuildYAML) { c.token = "" }, true},
		{"short bundle key", func(c *clientBuildYAML) { c.bundleKey = "short" }, true},
		{"empty platforms", func(c *clientBuildYAML) { c.platforms = "[]" }, true},
		{"duplicate platforms", func(c *clientBuildYAML) { c.platforms = "[linux-x64, linux-x64]" }, true},
		{"zero retention", func(c *clientBuildYAML) { c.retention = "0s" }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid
			tc.mutate(&cfg)
			path := writeConfig(t, cfg.String())
			_, err := config.Load(path)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func writeConfig(t *testing.T, clientBuild string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := `
server: {addr: ":8080"}
log: {level: info, format: json}
auth: {secret: "file-secret-file-secret-file-secret", accessTTL: 15m, refreshTTL: 168h}
` + clientBuild
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
	return path
}
