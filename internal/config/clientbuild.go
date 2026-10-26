package config

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type ClientBuildConfig struct {
	Enabled               bool                    `mapstructure:"enabled"`
	PublicBaseURL         string                  `mapstructure:"publicBaseURL"`
	AssetDir              string                  `mapstructure:"assetDir"`
	RustdeskVersion       string                  `mapstructure:"rustdeskVersion"`
	GitHub                ClientBuildGitHubConfig `mapstructure:"github"`
	Bundle                ClientBuildBundleConfig `mapstructure:"bundle"`
	PollInterval          time.Duration           `mapstructure:"pollInterval"`
	PendingTimeout        time.Duration           `mapstructure:"pendingTimeout"`
	DispatchTimeout       time.Duration           `mapstructure:"dispatchTimeout"`
	BuildTimeout          time.Duration           `mapstructure:"buildTimeout"`
	IngestTimeout         time.Duration           `mapstructure:"ingestTimeout"`
	ArtifactRetention     time.Duration           `mapstructure:"artifactRetention"`
	DeleteRemoteArtifacts bool                    `mapstructure:"deleteRemoteArtifacts"`
	MaxProfilesPerOrg     int                     `mapstructure:"maxProfilesPerOrg"`
	MaxConcurrentPerOrg   int                     `mapstructure:"maxConcurrentPerOrg"`
	MaxActiveBuilds       int                     `mapstructure:"maxActiveBuilds"`
	MaxArtifactBytes      int64                   `mapstructure:"maxArtifactBytes"`
	Platforms             []string                `mapstructure:"platforms"`
}

type ClientBuildGitHubConfig struct {
	APIBaseURL    string   `mapstructure:"apiBaseURL"`
	Repo          string   `mapstructure:"repo"`
	Workflow      string   `mapstructure:"workflow"`
	Ref           string   `mapstructure:"ref"`
	Token         string   `mapstructure:"token"`
	ArtifactHosts []string `mapstructure:"artifactHosts"`
}

type ClientBuildBundleConfig struct {
	TTL time.Duration `mapstructure:"ttl"`
	Key string        `mapstructure:"key"`
}

var (
	clientBuildVersionPattern = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	clientBuildRepoPattern    = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
)

func validateClientBuild(cfg ClientBuildConfig) error {
	if strings.TrimSpace(cfg.AssetDir) == "" {
		return fmt.Errorf("clientbuild.assetDir is required")
	}
	if cfg.PollInterval <= 0 || cfg.PendingTimeout <= 0 || cfg.DispatchTimeout <= 0 ||
		cfg.BuildTimeout <= 0 || cfg.IngestTimeout <= 0 || cfg.ArtifactRetention <= 0 ||
		cfg.Bundle.TTL <= 0 {
		return fmt.Errorf("clientbuild durations must be positive")
	}
	if cfg.MaxProfilesPerOrg <= 0 || cfg.MaxConcurrentPerOrg <= 0 || cfg.MaxActiveBuilds <= 0 ||
		cfg.MaxArtifactBytes <= 0 {
		return fmt.Errorf("clientbuild quotas must be positive")
	}
	if !clientBuildVersionPattern.MatchString(cfg.RustdeskVersion) {
		return fmt.Errorf("clientbuild.rustdeskVersion must be a semantic version, got %q", cfg.RustdeskVersion)
	}
	if len(cfg.Platforms) == 0 {
		return fmt.Errorf("clientbuild.platforms must not be empty")
	}
	seen := map[string]bool{}
	for _, platform := range cfg.Platforms {
		if strings.TrimSpace(platform) == "" {
			return fmt.Errorf("clientbuild.platforms contains an empty value")
		}
		if seen[platform] {
			return fmt.Errorf("clientbuild.platforms contains duplicate %q", platform)
		}
		seen[platform] = true
	}

	if !cfg.Enabled {
		return nil
	}

	u, err := url.Parse(strings.TrimSpace(cfg.PublicBaseURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
		u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("clientbuild.publicBaseURL must be an http(s) origin without path, query or fragment")
	}
	if !clientBuildRepoPattern.MatchString(cfg.GitHub.Repo) {
		return fmt.Errorf("clientbuild.github.repo must look like owner/name")
	}
	if strings.TrimSpace(cfg.GitHub.Workflow) == "" || strings.TrimSpace(cfg.GitHub.Ref) == "" ||
		strings.TrimSpace(cfg.GitHub.Token) == "" {
		return fmt.Errorf("clientbuild.github.workflow, ref and token are required when enabled")
	}
	if len(cfg.Bundle.Key) < 32 {
		return fmt.Errorf("clientbuild.bundle.key must be at least 32 bytes")
	}
	if len(cfg.GitHub.ArtifactHosts) == 0 {
		return fmt.Errorf("clientbuild.github.artifactHosts must not be empty when enabled")
	}
	for _, pattern := range cfg.GitHub.ArtifactHosts {
		if !validArtifactHostPattern(pattern) {
			return fmt.Errorf("clientbuild.github.artifactHosts contains invalid pattern %q", pattern)
		}
	}
	return nil
}

func validArtifactHostPattern(pattern string) bool {
	p := strings.ToLower(strings.TrimSpace(pattern))
	if strings.HasPrefix(p, "*.") {
		p = p[2:]
	}
	if p == "" || net.ParseIP(p) != nil {
		return false
	}
	if strings.ContainsAny(p, "/:@") || strings.HasPrefix(p, ".") || strings.HasSuffix(p, ".") ||
		strings.Contains(p, "..") {
		return false
	}
	for _, r := range p {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '.' && r != '-' {
			return false
		}
	}
	return true
}
