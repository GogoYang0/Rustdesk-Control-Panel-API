package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/clientbuild"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
)

func testClientBuildConfig(t *testing.T) config.Config {
	t.Helper()
	return config.Config{
		Provision: config.ProvisionConfig{RelayHost: "relay.example.com"},
		ClientBuild: config.ClientBuildConfig{
			Enabled:         true,
			PublicBaseURL:   "https://panel.example.com",
			AssetDir:        t.TempDir(),
			RustdeskVersion: "1.5.0",
			GitHub: config.ClientBuildGitHubConfig{
				APIBaseURL: "https://api.github.com", Repo: "acme/build",
				Workflow: "build-client.yml", Ref: "main", Token: "pat",
				ArtifactHosts: []string{"github.com", "*.blob.core.windows.net"},
			},
			Bundle: config.ClientBuildBundleConfig{
				TTL: 24 * time.Hour, Key: "0123456789abcdef0123456789abcdef",
			},
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
			Platforms:             append([]string{}, clientbuild.SupportedPlatforms...),
		},
	}
}

func TestClientBuildRuntimeConfig(t *testing.T) {
	cfg := testClientBuildConfig(t)
	runtime := clientBuildRuntimeConfig(cfg)
	require.Equal(t, "relay.example.com", runtime.RelayHost)
	require.Equal(t, cfg.ClientBuild.Enabled, runtime.Enabled)
	require.Equal(t, cfg.ClientBuild.PublicBaseURL, runtime.PublicBaseURL)
	require.Equal(t, cfg.ClientBuild.AssetDir, runtime.AssetDir)
	require.Equal(t, cfg.ClientBuild.RustdeskVersion, runtime.RustdeskVersion)
	require.Equal(t, cfg.ClientBuild.GitHub.APIBaseURL, runtime.GitHub.APIBaseURL)
	require.Equal(t, cfg.ClientBuild.GitHub.Repo, runtime.GitHub.Repo)
	require.Equal(t, cfg.ClientBuild.GitHub.Workflow, runtime.GitHub.Workflow)
	require.Equal(t, cfg.ClientBuild.GitHub.Ref, runtime.GitHub.Ref)
	require.Equal(t, cfg.ClientBuild.GitHub.Token, runtime.GitHub.Token)
	require.Equal(t, cfg.ClientBuild.GitHub.ArtifactHosts, runtime.GitHub.ArtifactHosts)
	require.Equal(t, cfg.ClientBuild.Bundle.TTL, runtime.BundleTTL)
	require.Equal(t, cfg.ClientBuild.Bundle.Key, runtime.BundleKey)
	require.Equal(t, cfg.ClientBuild.PollInterval, runtime.PollInterval)
	require.Equal(t, cfg.ClientBuild.PendingTimeout, runtime.PendingTimeout)
	require.Equal(t, cfg.ClientBuild.DispatchTimeout, runtime.DispatchTimeout)
	require.Equal(t, cfg.ClientBuild.BuildTimeout, runtime.BuildTimeout)
	require.Equal(t, cfg.ClientBuild.IngestTimeout, runtime.IngestTimeout)
	require.Equal(t, cfg.ClientBuild.ArtifactRetention, runtime.ArtifactRetention)
	require.Equal(t, cfg.ClientBuild.DeleteRemoteArtifacts, runtime.DeleteRemoteArtifacts)
	require.Equal(t, cfg.ClientBuild.MaxProfilesPerOrg, runtime.MaxProfilesPerOrg)
	require.Equal(t, cfg.ClientBuild.MaxConcurrentPerOrg, runtime.MaxConcurrentPerOrg)
	require.Equal(t, cfg.ClientBuild.MaxActiveBuilds, runtime.MaxActiveBuilds)
	require.Equal(t, cfg.ClientBuild.MaxArtifactBytes, runtime.MaxArtifactBytes)
	require.Equal(t, cfg.ClientBuild.Platforms, runtime.Platforms)
}

func TestNewClientBuildServiceValidation(t *testing.T) {
	cfg := testClientBuildConfig(t)
	svc, err := newClientBuildService(cfg, nil, nil, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, svc)

	bad := cfg
	bad.ClientBuild.Platforms = []string{"ios"}
	_, err = newClientBuildService(bad, nil, nil, nil, nil)
	require.Error(t, err)

	short := cfg
	short.ClientBuild.Bundle.Key = "short"
	_, err = newClientBuildService(short, nil, nil, nil, nil)
	require.Error(t, err)
}
