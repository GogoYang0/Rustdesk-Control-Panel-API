package main

import (
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/clientbuild"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
)

func clientBuildRuntimeConfig(cfg config.Config) clientbuild.Config {
	cb := cfg.ClientBuild
	return clientbuild.Config{
		Enabled:         cb.Enabled,
		PublicBaseURL:   cb.PublicBaseURL,
		RelayHost:       cfg.Provision.RelayHost,
		AssetDir:        cb.AssetDir,
		RustdeskVersion: cb.RustdeskVersion,
		GitHub: clientbuild.GitHubConfig{
			APIBaseURL:    cb.GitHub.APIBaseURL,
			Repo:          cb.GitHub.Repo,
			Workflow:      cb.GitHub.Workflow,
			Ref:           cb.GitHub.Ref,
			Token:         cb.GitHub.Token,
			ArtifactHosts: append([]string{}, cb.GitHub.ArtifactHosts...),
		},
		BundleTTL:             cb.Bundle.TTL,
		BundleKey:             cb.Bundle.Key,
		PollInterval:          cb.PollInterval,
		PendingTimeout:        cb.PendingTimeout,
		DispatchTimeout:       cb.DispatchTimeout,
		BuildTimeout:          cb.BuildTimeout,
		IngestTimeout:         cb.IngestTimeout,
		ArtifactRetention:     cb.ArtifactRetention,
		DeleteRemoteArtifacts: cb.DeleteRemoteArtifacts,
		MaxProfilesPerOrg:     cb.MaxProfilesPerOrg,
		MaxConcurrentPerOrg:   cb.MaxConcurrentPerOrg,
		MaxActiveBuilds:       cb.MaxActiveBuilds,
		MaxArtifactBytes:      cb.MaxArtifactBytes,
		Platforms:             append([]string{}, cb.Platforms...),
	}
}

func newClientBuildService(
	cfg config.Config,
	db *gorm.DB,
	recorder audit.TxRecorder,
	auditor audit.Auditor,
	logger *zap.Logger,
) (*clientbuild.Service, error) {
	runtime := clientBuildRuntimeConfig(cfg)
	github := clientbuild.NewGitHubClient(runtime.GitHub, logger)
	return clientbuild.NewService(db, recorder, auditor, runtime, github, logger, nil)
}
