package config

import (
	"fmt"
	"net/url"
	"regexp"
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

// LDAPConfig describes the single directory the deployment delegates
// authentication to. BindPassword is never read from the tracked file: Load
// fills it from PANEL_LDAP_BIND_PASSWORD (design L4).
type LDAPConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	ProviderName string `mapstructure:"providerName"`
	Host         string `mapstructure:"host"`
	Port         int    `mapstructure:"port"`
	Transport    string `mapstructure:"transport"` // ldaps | starttls | none
	// AllowInsecure is required for Transport "none": directory passwords over
	// a plaintext link are readable by anyone on the path (design L3).
	AllowInsecure bool `mapstructure:"allowInsecure"`
	// InsecureSkipVerify turns off the LDAPS certificate chain check.
	InsecureSkipVerify bool          `mapstructure:"insecureSkipVerify"`
	BaseDN             string        `mapstructure:"baseDN"`
	Scope              string        `mapstructure:"scope"` // one | sub
	BindDN             string        `mapstructure:"bindDN"`
	UserFilter         string        `mapstructure:"userFilter"`
	UsernameAttribute  string        `mapstructure:"usernameAttribute"`
	MailAttribute      string        `mapstructure:"mailAttribute"`
	Timeout            time.Duration `mapstructure:"timeout"`
	BindPassword       string        `mapstructure:"-"`
}

const (
	ldapMaxFilterLength = 512
	ldapMaxTimeout      = 30 * time.Second
)

var attributeNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*$`)

// Warnings lists the transport decisions an operator must not miss: plaintext
// links broadcast the directory password, and skipping the certificate check
// turns LDAPS into plaintext with extra steps (design L3).
func (c LDAPConfig) Warnings() []string {
	var out []string
	if c.Enabled && c.Transport == "none" {
		out = append(out, "ldap.transport=none sends directory passwords in plaintext; enable only on a trusted isolated network")
	}
	if c.Enabled && c.InsecureSkipVerify {
		out = append(out, "ldap.insecureSkipVerify=true disables the directory certificate check; enable only for self-signed test directories")
	}
	return out
}

// validateLDAP refuses a half-configured directory rather than booting with
// endpoints that can only answer 503.
func validateLDAP(cfg LDAPConfig) error {
	if !cfg.Enabled {
		return nil
	}
	if strings.TrimSpace(cfg.Host) == "" {
		return fmt.Errorf("ldap.host is required")
	}
	if strings.TrimSpace(cfg.BaseDN) == "" {
		return fmt.Errorf("ldap.baseDN is required")
	}
	if strings.TrimSpace(cfg.BindDN) == "" {
		return fmt.Errorf("ldap.bindDN is required")
	}
	if cfg.BindPassword == "" {
		return fmt.Errorf("PANEL_LDAP_BIND_PASSWORD is required when ldap.enabled is true")
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return fmt.Errorf("ldap.port must be between 1 and 65535")
	}
	switch cfg.Transport {
	case "ldaps", "starttls":
	case "none":
		if !cfg.AllowInsecure {
			return fmt.Errorf("ldap.transport=none requires ldap.allowInsecure=true: directory passwords in plaintext are readable by anyone on the path")
		}
	default:
		return fmt.Errorf("ldap.transport must be ldaps, starttls or none, got %q", cfg.Transport)
	}
	for name, label := range map[string]string{
		cfg.UsernameAttribute: "ldap.usernameAttribute",
		cfg.MailAttribute:     "ldap.mailAttribute",
	} {
		if !attributeNamePattern.MatchString(name) {
			return fmt.Errorf("%s must match ^[A-Za-z][A-Za-z0-9-]*$, got %q", label, name)
		}
	}
	// The filter is spliced into the search request verbatim, so its shape is
	// checked at startup rather than trusted from the request path.
	filter := cfg.UserFilter
	if !strings.HasPrefix(filter, "(") || !strings.HasSuffix(filter, ")") {
		return fmt.Errorf("ldap.userFilter must be a parenthesised filter, got %q", filter)
	}
	if len(filter) > ldapMaxFilterLength {
		return fmt.Errorf("ldap.userFilter must not exceed %d characters", ldapMaxFilterLength)
	}
	// Unbalanced parentheses pass the prefix/suffix and assertion checks but
	// make every search a protocol error: the deployment would boot into
	// permanent 503s instead of failing at startup.
	depth := 0
	for _, r := range filter {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return fmt.Errorf("ldap.userFilter has unbalanced parentheses: %q", filter)
			}
		}
	}
	if depth != 0 {
		return fmt.Errorf("ldap.userFilter has unbalanced parentheses: %q", filter)
	}
	// A filter that never references an attribute (e.g. "(&)") matches
	// everything-or-nothing in ways the operator did not intend: there must be
	// at least one assertion "(attr=value)" or one presence check "(attr)".
	hasAssertion := regexp.MustCompile(`\([^()=]+=[^()]*\)`).MatchString(filter)
	hasPresence := regexp.MustCompile(`\([A-Za-z][^()=]*\)`).MatchString(filter)
	if !hasAssertion && !hasPresence {
		return fmt.Errorf("ldap.userFilter must reference at least one attribute condition, got %q", filter)
	}
	switch cfg.Scope {
	case "one", "sub":
	default:
		return fmt.Errorf("ldap.scope must be one or sub, got %q", cfg.Scope)
	}
	if cfg.Timeout <= 0 || cfg.Timeout > ldapMaxTimeout {
		return fmt.Errorf("ldap.timeout must be between 1s and 30s")
	}
	return nil
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

// validateProviders enforces the single-provider rule (design L10).
func validateProviders(oidc OIDCConfig, ldap LDAPConfig) error {
	if oidc.Enabled && ldap.Enabled {
		return fmt.Errorf("oidc.enabled and ldap.enabled are mutually exclusive")
	}
	return nil
}
