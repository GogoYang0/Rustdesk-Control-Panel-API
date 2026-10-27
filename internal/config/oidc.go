package config

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Defaults for the OIDC section. They are what an operator who only flips
// enabled sees, so they must be safe: short-lived state, a minute of clock
// skew, and the standard scopes.
const (
	defaultOIDCProviderName = "Single sign-on"
	defaultOIDCClockSkew    = time.Minute
	defaultOIDCStateTTL     = 10 * time.Minute
	maxOIDCStateTTL         = 30 * time.Minute
	maxOIDCClockSkew        = 5 * time.Minute
)

// OIDCConfig describes the single, deployment-wide identity provider.
// ClientSecret is never read from the tracked file: Load fills it from
// PANEL_OIDC_CLIENT_SECRET so a secret cannot leak through git.
type OIDCConfig struct {
	Enabled      bool          `mapstructure:"enabled"`
	ProviderName string        `mapstructure:"providerName"`
	Issuer       string        `mapstructure:"issuer"`
	ClientID     string        `mapstructure:"clientID"`
	Scopes       []string      `mapstructure:"scopes"`
	ClockSkew    time.Duration `mapstructure:"clockSkew"`
	StateTTL     time.Duration `mapstructure:"stateTTL"`
	ClientSecret string        `mapstructure:"-"`
}

// ExternalConfig tunes how external identities relate to local factors.
type ExternalConfig struct {
	// RequireLocalSecondFactor makes an external login still ask for the
	// panel's own TOTP, but only for accounts that already enabled it
	// (design O12). Accounts without TOTP are let through with a warning,
	// otherwise they could never sign in.
	RequireLocalSecondFactor bool `mapstructure:"requireLocalSecondFactor"`
}

// LDAPConfig is reserved for 5b-3. Only the mutual exclusion is enforced now;
// enabling it in this build fails fast instead of pretending to work.
type LDAPConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

// validateOIDC refuses a half-configured provider rather than booting with
// endpoints that can only answer 503.
func validateOIDC(cfg OIDCConfig, webBaseURL string) error {
	if !cfg.Enabled {
		return nil
	}
	issuer := strings.TrimSpace(cfg.Issuer)
	if issuer == "" {
		return fmt.Errorf("oidc.issuer is required")
	}
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Host == "" || parsed.Scheme != "https" {
		return fmt.Errorf("oidc.issuer must be an https URL")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("oidc.issuer must not carry a query or fragment")
	}
	if strings.TrimSpace(cfg.ClientID) == "" {
		return fmt.Errorf("oidc.clientID is required")
	}
	if cfg.ClientSecret == "" {
		return fmt.Errorf("PANEL_OIDC_CLIENT_SECRET is required when oidc.enabled is true")
	}
	hasOpenID, hasEmail := false, false
	for _, scope := range cfg.Scopes {
		switch strings.TrimSpace(scope) {
		case "openid":
			hasOpenID = true
		case "email":
			hasEmail = true
		}
	}
	if !hasOpenID {
		return fmt.Errorf("oidc.scopes must include openid")
	}
	if !hasEmail {
		return fmt.Errorf("oidc.scopes must include email")
	}
	if cfg.StateTTL <= 0 || cfg.StateTTL > maxOIDCStateTTL {
		return fmt.Errorf("oidc.stateTTL must be between 1s and 30m")
	}
	if cfg.ClockSkew < 0 || cfg.ClockSkew > maxOIDCClockSkew {
		return fmt.Errorf("oidc.clockSkew must be between 0 and 5m")
	}
	return validateOIDCWebBaseURL(webBaseURL)
}

// validateOIDCWebBaseURL checks the origin the callback URL is derived from.
// It must be https, except for the loopback hosts browsers treat as secure
// contexts during local development.
func validateOIDCWebBaseURL(raw string) error {
	base := strings.TrimSpace(raw)
	if base == "" {
		return fmt.Errorf("web.baseURL is required when oidc.enabled is true")
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.Host == "" {
		return fmt.Errorf("web.baseURL must be an absolute origin when oidc.enabled is true")
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname()) {
		return nil
	}
	return fmt.Errorf("web.baseURL must be https when oidc.enabled is true")
}

// validateProviders enforces the single-provider rule (design O1). LDAP is
// checked last so a deployment flipping both learns about the real conflict
// rather than the not-implemented error.
func validateProviders(oidc OIDCConfig, ldap LDAPConfig) error {
	if oidc.Enabled && ldap.Enabled {
		return fmt.Errorf("oidc.enabled and ldap.enabled are mutually exclusive")
	}
	if ldap.Enabled {
		return fmt.Errorf("ldap.enabled is not available in this build")
	}
	return nil
}
