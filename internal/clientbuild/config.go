package clientbuild

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

const (
	PlatformWindowsX64   = model.ClientBuildPlatformWindowsX64
	PlatformLinuxX64     = model.ClientBuildPlatformLinuxX64
	PlatformMacOSARM64   = model.ClientBuildPlatformMacOSARM64
	PlatformMacOSX64     = model.ClientBuildPlatformMacOSX64
	PlatformAndroidARM64 = model.ClientBuildPlatformAndroidARM64
)

var SupportedPlatforms = []string{
	PlatformWindowsX64,
	PlatformLinuxX64,
	PlatformMacOSARM64,
	PlatformMacOSX64,
	PlatformAndroidARM64,
}

type Config struct {
	Enabled               bool
	PublicBaseURL         string
	RelayHost             string
	AssetDir              string
	RustdeskVersion       string
	GitHub                GitHubConfig
	BundleTTL             time.Duration
	BundleKey             string
	PollInterval          time.Duration
	PendingTimeout        time.Duration
	DispatchTimeout       time.Duration
	BuildTimeout          time.Duration
	IngestTimeout         time.Duration
	ArtifactRetention     time.Duration
	DeleteRemoteArtifacts bool
	MaxProfilesPerOrg     int
	MaxConcurrentPerOrg   int
	MaxActiveBuilds       int
	MaxArtifactBytes      int64
	Platforms             []string
}

type GitHubConfig struct {
	APIBaseURL    string
	Repo          string
	Workflow      string
	Ref           string
	Token         string
	ArtifactHosts []string
}

var (
	versionPattern = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	repoPattern    = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
)

func ValidateConfig(cfg Config) error {
	if strings.TrimSpace(cfg.AssetDir) == "" {
		return fmt.Errorf("clientbuild asset dir is required")
	}
	if cfg.PollInterval <= 0 || cfg.PendingTimeout <= 0 || cfg.DispatchTimeout <= 0 ||
		cfg.BuildTimeout <= 0 || cfg.IngestTimeout <= 0 || cfg.ArtifactRetention <= 0 ||
		cfg.BundleTTL <= 0 {
		return fmt.Errorf("clientbuild durations must be positive")
	}
	if cfg.MaxProfilesPerOrg <= 0 || cfg.MaxConcurrentPerOrg <= 0 || cfg.MaxActiveBuilds <= 0 ||
		cfg.MaxArtifactBytes <= 0 {
		return fmt.Errorf("clientbuild quotas must be positive")
	}
	if !versionPattern.MatchString(cfg.RustdeskVersion) {
		return fmt.Errorf("clientbuild rustdesk version must be a semantic version")
	}
	if len(cfg.Platforms) == 0 {
		return fmt.Errorf("clientbuild platforms must not be empty")
	}
	seen := map[string]bool{}
	for _, platform := range cfg.Platforms {
		if strings.TrimSpace(platform) == "" {
			return fmt.Errorf("clientbuild platforms contains an empty value")
		}
		if seen[platform] {
			return fmt.Errorf("clientbuild platforms contains duplicate %q", platform)
		}
		seen[platform] = true
	}
	if _, err := ValidatePlatforms(cfg.Platforms, SupportedPlatforms); err != nil {
		return err
	}
	if !cfg.Enabled {
		return nil
	}

	u, err := url.Parse(strings.TrimSpace(cfg.PublicBaseURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
		u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("clientbuild public base URL must be an http(s) origin")
	}
	if strings.TrimSpace(cfg.RelayHost) == "" {
		return fmt.Errorf("clientbuild relay host is required")
	}
	if !repoPattern.MatchString(cfg.GitHub.Repo) {
		return fmt.Errorf("clientbuild github repo must look like owner/name")
	}
	if strings.TrimSpace(cfg.GitHub.Workflow) == "" || strings.TrimSpace(cfg.GitHub.Ref) == "" ||
		strings.TrimSpace(cfg.GitHub.Token) == "" {
		return fmt.Errorf("clientbuild github workflow, ref and token are required")
	}
	api, err := url.Parse(strings.TrimSpace(cfg.GitHub.APIBaseURL))
	if err != nil || (api.Scheme != "http" && api.Scheme != "https") || api.Host == "" {
		return fmt.Errorf("clientbuild github API base URL must be http(s)")
	}
	if len(cfg.BundleKey) < 32 {
		return fmt.Errorf("clientbuild bundle key must be at least 32 bytes")
	}
	if len(cfg.GitHub.ArtifactHosts) == 0 {
		return fmt.Errorf("clientbuild artifact hosts must not be empty")
	}
	for _, pattern := range cfg.GitHub.ArtifactHosts {
		if !validArtifactHost(pattern) {
			return fmt.Errorf("clientbuild artifact host pattern %q is invalid", pattern)
		}
	}
	return nil
}

func validArtifactHost(pattern string) bool {
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
