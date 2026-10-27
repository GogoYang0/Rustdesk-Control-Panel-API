package config

import (
	"strings"
	"testing"
	"time"
)

// webAuthnOK is the minimal valid configuration every negative case mutates.
func webAuthnOK() WebAuthnConfig {
	return WebAuthnConfig{
		Enabled:            true,
		RPID:               "panel.example.com",
		RPDisplayName:      "RustDesk Control Panel",
		Origin:             "https://panel.example.com",
		CeremonyTTL:        5 * time.Minute,
		CredentialsPerUser: 10,
	}
}

func mutateWebAuthn(f func(*WebAuthnConfig)) WebAuthnConfig {
	cfg := webAuthnOK()
	f(&cfg)
	return cfg
}

func TestValidateWebAuthn(t *testing.T) {
	cases := []struct {
		name    string
		cfg     WebAuthnConfig
		wantErr string
	}{
		{"disabled skips validation", WebAuthnConfig{}, ""},
		{"valid https origin", webAuthnOK(), ""},
		{"subdomain origin under rpId", mutateWebAuthn(func(c *WebAuthnConfig) {
			c.RPID = "example.com"
			c.Origin = "https://panel.example.com"
		}), ""},
		{"ip rpId rejected", mutateWebAuthn(func(c *WebAuthnConfig) {
			c.RPID = "127.0.0.1"
			c.Origin = "http://127.0.0.1:8080"
		}), "webauthn.rpId must be a domain name"},
		{"localhost over http", mutateWebAuthn(func(c *WebAuthnConfig) {
			c.RPID = "localhost"
			c.Origin = "http://localhost:5173"
		}), ""},
		{"missing rpId", mutateWebAuthn(func(c *WebAuthnConfig) { c.RPID = "" }), "webauthn.rpId is required"},
		{"rpId with scheme", mutateWebAuthn(func(c *WebAuthnConfig) { c.RPID = "https://panel.example.com" }), "webauthn.rpId must be a bare lowercase host"},
		{"rpId uppercase", mutateWebAuthn(func(c *WebAuthnConfig) { c.RPID = "Panel.Example.com" }), "webauthn.rpId must be a bare lowercase host"},
		{"rpId with port", mutateWebAuthn(func(c *WebAuthnConfig) { c.RPID = "panel.example.com:8443" }), "webauthn.rpId must be a bare lowercase host"},
		{"missing origin", mutateWebAuthn(func(c *WebAuthnConfig) { c.Origin = "" }), "webauthn.origin is required"},
		{"public origin over http", mutateWebAuthn(func(c *WebAuthnConfig) { c.Origin = "http://panel.example.com" }), "webauthn.origin must use https"},
		{"origin with path", mutateWebAuthn(func(c *WebAuthnConfig) { c.Origin = "https://panel.example.com/app" }), "webauthn.origin must not carry a path, query or fragment"},
		{"origin with query", mutateWebAuthn(func(c *WebAuthnConfig) { c.Origin = "https://panel.example.com?x=1" }), "webauthn.origin must not carry a path, query or fragment"},
		{"rpId not a suffix of the origin", mutateWebAuthn(func(c *WebAuthnConfig) { c.Origin = "https://evil.example.org" }), "webauthn.rpId must be a suffix of the origin host"},
		{"ttl zero", mutateWebAuthn(func(c *WebAuthnConfig) { c.CeremonyTTL = 0 }), "webauthn.ceremonyTTL must be between 1s and 15m"},
		{"ttl too long", mutateWebAuthn(func(c *WebAuthnConfig) { c.CeremonyTTL = 16 * time.Minute }), "webauthn.ceremonyTTL must be between 1s and 15m"},
		{"no credentials allowed", mutateWebAuthn(func(c *WebAuthnConfig) { c.CredentialsPerUser = 0 }), "webauthn.credentialsPerUser must be between 1 and 20"},
		{"too many credentials", mutateWebAuthn(func(c *WebAuthnConfig) { c.CredentialsPerUser = 21 }), "webauthn.credentialsPerUser must be between 1 and 20"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateWebAuthn(tc.cfg)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}
