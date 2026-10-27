package clientbuild

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func validConfig() Config {
	return Config{
		Enabled:         true,
		PublicBaseURL:   "https://panel.example.com",
		RelayHost:       "relay.example.com",
		AssetDir:        "./data/client-builds",
		RustdeskVersion: "1.5.0",
		GitHub: GitHubConfig{
			APIBaseURL:    "https://api.github.com",
			Repo:          "acme/build",
			Workflow:      "build-client.yml",
			Ref:           "main",
			Token:         "pat",
			ArtifactHosts: []string{"github.com", "*.blob.core.windows.net"},
		},
		BundleTTL:             24 * time.Hour,
		BundleKey:             "0123456789abcdef0123456789abcdef",
		PollInterval:          30 * time.Second,
		PendingTimeout:        12 * time.Hour,
		DispatchTimeout:       10 * time.Minute,
		BuildTimeout:          3 * time.Hour,
		IngestTimeout:         time.Hour,
		ArtifactRetention:     720 * time.Hour,
		DeleteRemoteArtifacts: true,
		MaxProfilesPerOrg:     10,
		MaxConcurrentPerOrg:   2,
		MaxActiveBuilds:       4,
		MaxArtifactBytes:      2 << 30,
		Platforms:             append([]string{}, SupportedPlatforms...),
	}
}

func TestValidateConfig(t *testing.T) {
	require.NoError(t, ValidateConfig(validConfig()))

	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"unknown platform", func(c *Config) { c.Platforms = []string{"ios"} }},
		{"short bundle key", func(c *Config) { c.BundleKey = "short" }},
		{"empty asset dir", func(c *Config) { c.AssetDir = "" }},
		{"non-positive timeout", func(c *Config) { c.BuildTimeout = 0 }},
		{"missing public base url", func(c *Config) { c.PublicBaseURL = "" }},
		{"missing repo", func(c *Config) { c.GitHub.Repo = "" }},
		{"missing token", func(c *Config) { c.GitHub.Token = "" }},
		{"missing artifact hosts", func(c *Config) { c.GitHub.ArtifactHosts = nil }},
		{"missing relay host", func(c *Config) { c.RelayHost = "" }},
		// Both URLs carry credentials: the bundle token rides PublicBaseURL and
		// the PAT rides APIBaseURL, so cleartext is only tolerated on loopback.
		{"cleartext public base url", func(c *Config) { c.PublicBaseURL = "http://panel.example.com" }},
		{"cleartext github api", func(c *Config) { c.GitHub.APIBaseURL = "http://api.github.com" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.mutate(&cfg)
			require.Error(t, ValidateConfig(cfg))
		})
	}
}

func TestValidateConfig_AllowsLoopbackCleartext(t *testing.T) {
	for _, base := range []string{
		"http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080",
	} {
		cfg := validConfig()
		cfg.PublicBaseURL = base
		cfg.GitHub.APIBaseURL = base
		require.NoError(t, ValidateConfig(cfg), base)
	}
}
