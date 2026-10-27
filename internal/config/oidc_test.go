package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// oidcOK is the minimal valid configuration every negative case mutates.
func oidcOK() OIDCConfig {
	return OIDCConfig{
		Enabled:      true,
		ProviderName: "Single sign-on",
		Issuer:       "https://idp.example.com",
		ClientID:     "panel",
		ClientSecret: "s3cret-value",
		Scopes:       []string{"openid", "profile", "email"},
		ClockSkew:    time.Minute,
		StateTTL:     10 * time.Minute,
	}
}

func mutateOIDC(f func(*OIDCConfig)) OIDCConfig {
	cfg := oidcOK()
	f(&cfg)
	return cfg
}

func TestValidateOIDC(t *testing.T) {
	cases := []struct {
		name    string
		cfg     OIDCConfig
		web     string
		wantErr string
	}{
		{"disabled skips validation", OIDCConfig{}, "", ""},
		{"valid https deployment", oidcOK(), "https://panel.example.com", ""},
		{"localhost http is a secure context", oidcOK(), "http://localhost:5173", ""},
		{"issuer required", mutateOIDC(func(c *OIDCConfig) { c.Issuer = "" }), "https://panel.example.com", "oidc.issuer is required"},
		{"issuer must be https", mutateOIDC(func(c *OIDCConfig) { c.Issuer = "http://idp.example.com" }), "https://panel.example.com", "oidc.issuer must be an https URL"},
		{"issuer must not carry a query", mutateOIDC(func(c *OIDCConfig) { c.Issuer = "https://idp.example.com/?a=1" }), "https://panel.example.com", "oidc.issuer must not carry a query or fragment"},
		{"client id required", mutateOIDC(func(c *OIDCConfig) { c.ClientID = "" }), "https://panel.example.com", "oidc.clientID is required"},
		{"client secret required", mutateOIDC(func(c *OIDCConfig) { c.ClientSecret = "" }), "https://panel.example.com", "PANEL_OIDC_CLIENT_SECRET is required"},
		{"scopes need openid", mutateOIDC(func(c *OIDCConfig) { c.Scopes = []string{"email"} }), "https://panel.example.com", "oidc.scopes must include openid"},
		{"scopes need email", mutateOIDC(func(c *OIDCConfig) { c.Scopes = []string{"openid", "profile"} }), "https://panel.example.com", "oidc.scopes must include email"},
		{"state ttl must be positive", mutateOIDC(func(c *OIDCConfig) { c.StateTTL = 0 }), "https://panel.example.com", "oidc.stateTTL must be between 1s and 30m"},
		{"state ttl upper bound", mutateOIDC(func(c *OIDCConfig) { c.StateTTL = 31 * time.Minute }), "https://panel.example.com", "oidc.stateTTL must be between 1s and 30m"},
		{"clock skew upper bound", mutateOIDC(func(c *OIDCConfig) { c.ClockSkew = 10 * time.Minute }), "https://panel.example.com", "oidc.clockSkew must be between 0 and 5m"},
		{"web base url required", oidcOK(), "", "web.baseURL is required"},
		{"web base url must be https", oidcOK(), "http://panel.example.com", "web.baseURL must be https"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateOIDC(tc.cfg, tc.web)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validateOIDC() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validateOIDC() = nil, want error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("validateOIDC() = %q, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestValidateProviders(t *testing.T) {
	cases := []struct {
		name    string
		oidc    OIDCConfig
		ldap    LDAPConfig
		wantErr string
	}{
		{"both disabled", OIDCConfig{}, LDAPConfig{}, ""},
		{"oidc only", oidcOK(), LDAPConfig{}, ""},
		{
			"ldap is not implemented in this build",
			OIDCConfig{}, LDAPConfig{Enabled: true},
			"ldap.enabled is not available in this build",
		},
		{
			"providers are mutually exclusive",
			oidcOK(), LDAPConfig{Enabled: true},
			"oidc.enabled and ldap.enabled are mutually exclusive",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateProviders(tc.oidc, tc.ldap)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validateProviders() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("validateProviders() = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestLoad_OIDCSection(t *testing.T) {
	t.Setenv("PANEL_AUTH_SECRET", "test-secret-test-secret-test-secret")
	t.Setenv("PANEL_OIDC_CLIENT_SECRET", "env-secret-value")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(`
server: {addr: ":8080"}
log: {level: info, format: json}
auth: {secret: "", accessTTL: 15m, refreshTTL: 168h}
web: {baseURL: "https://panel.example.com"}
oidc:
  enabled: true
  issuer: "https://idp.example.com"
  clientID: "panel"
  clientSecret: "must-be-ignored"
external:
  requireLocalSecondFactor: true
`), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.OIDC.Enabled {
		t.Fatal("oidc.enabled = false, want true")
	}
	if cfg.OIDC.Issuer != "https://idp.example.com" || cfg.OIDC.ClientID != "panel" {
		t.Fatalf("oidc section not mapped: %+v", cfg.OIDC)
	}
	// The secret only ever comes from the environment: a value in the tracked
	// file must not be able to override it (or be mistaken for it).
	if cfg.OIDC.ClientSecret != "env-secret-value" {
		t.Fatalf("client secret = %q, want the environment value", cfg.OIDC.ClientSecret)
	}
	if cfg.OIDC.ProviderName != "Single sign-on" {
		t.Fatalf("providerName default = %q", cfg.OIDC.ProviderName)
	}
	if cfg.OIDC.StateTTL != 10*time.Minute || cfg.OIDC.ClockSkew != time.Minute {
		t.Fatalf("ttl defaults = %v / %v", cfg.OIDC.StateTTL, cfg.OIDC.ClockSkew)
	}
	if got, want := strings.Join(cfg.OIDC.Scopes, ","), "openid,profile,email"; got != want {
		t.Fatalf("scopes = %q, want %q", got, want)
	}
	if !cfg.External.RequireLocalSecondFactor {
		t.Fatal("external.requireLocalSecondFactor = false, want true")
	}
}

func TestLoad_OIDCRequiresEnvSecret(t *testing.T) {
	t.Setenv("PANEL_AUTH_SECRET", "test-secret-test-secret-test-secret")
	t.Setenv("PANEL_OIDC_CLIENT_SECRET", "")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(`
server: {addr: ":8080"}
log: {level: info, format: json}
auth: {secret: "", accessTTL: 15m, refreshTTL: 168h}
web: {baseURL: "https://panel.example.com"}
oidc:
  enabled: true
  issuer: "https://idp.example.com"
  clientID: "panel"
  clientSecret: "file-copy-must-not-save-us"
`), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "PANEL_OIDC_CLIENT_SECRET") {
		t.Fatalf("Load() error = %v, want a missing-secret error", err)
	}
}
