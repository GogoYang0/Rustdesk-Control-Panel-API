package config

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// WebAuthnConfig enables passkey (WebAuthn) login. The Relying Party identity
// is deployment-wide: one RP ID and one origin, matching how the panel is
// exposed to browsers. There are no secrets in this section.
type WebAuthnConfig struct {
	Enabled            bool          `mapstructure:"enabled"`
	RPID               string        `mapstructure:"rpId"`
	RPDisplayName      string        `mapstructure:"rpName"`
	Origin             string        `mapstructure:"origin"`
	CeremonyTTL        time.Duration `mapstructure:"ceremonyTTL"`
	CredentialsPerUser int           `mapstructure:"credentialsPerUser"`
}

const (
	defaultWebAuthnDisplayName = "RustDesk Control Panel"
	maxWebAuthnCeremonyTTL     = 15 * time.Minute
	maxWebAuthnCredentials     = 20
)

// webAuthnHostPattern accepts a bare lowercase DNS name or an IPv4 literal.
// Paths, ports and schemes are rejected: an RP ID is a host, nothing else.
var webAuthnHostPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

// validateWebAuthn refuses a half-configured provider instead of booting with
// passkey endpoints that can never complete a ceremony.
func validateWebAuthn(cfg WebAuthnConfig) error {
	if !cfg.Enabled {
		return nil
	}
	if strings.TrimSpace(cfg.RPID) == "" {
		return fmt.Errorf("webauthn.rpId is required")
	}
	if !webAuthnHostPattern.MatchString(cfg.RPID) {
		return fmt.Errorf("webauthn.rpId must be a bare lowercase host")
	}
	// WebAuthn RP IDs are domain names; browsers reject an IP literal with a
	// SecurityError, so a deployment configured that way would fail every
	// ceremony. localhost is the only loopback host that works.
	if net.ParseIP(cfg.RPID) != nil {
		return fmt.Errorf("webauthn.rpId must be a domain name (localhost for local testing), not an IP address")
	}
	if strings.TrimSpace(cfg.Origin) == "" {
		return fmt.Errorf("webauthn.origin is required")
	}
	u, err := url.Parse(cfg.Origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return fmt.Errorf("webauthn.origin must be an http(s) origin")
	}
	if u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("webauthn.origin must not carry a path, query or fragment")
	}
	host := u.Hostname()
	if u.Scheme == "http" && !isLoopbackHost(host) {
		return fmt.Errorf("webauthn.origin must use https (http is allowed only for loopback)")
	}
	if host != cfg.RPID && !strings.HasSuffix(host, "."+cfg.RPID) {
		return fmt.Errorf("webauthn.rpId must be a suffix of the origin host")
	}
	if cfg.CeremonyTTL < time.Second || cfg.CeremonyTTL > maxWebAuthnCeremonyTTL {
		return fmt.Errorf("webauthn.ceremonyTTL must be between 1s and 15m")
	}
	if cfg.CredentialsPerUser < 1 || cfg.CredentialsPerUser > maxWebAuthnCredentials {
		return fmt.Errorf("webauthn.credentialsPerUser must be between 1 and 20")
	}
	return nil
}

func isLoopbackHost(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1", "[::1]":
		return true
	}
	return false
}
