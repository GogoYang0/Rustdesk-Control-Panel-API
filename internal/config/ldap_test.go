package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ldapOK is the minimal valid configuration every negative case mutates.
func ldapOK() LDAPConfig {
	return LDAPConfig{
		Enabled:           true,
		ProviderName:      "Directory",
		Host:              "ldap.example.com",
		Port:              636,
		Transport:         "ldaps",
		BaseDN:            "dc=example,dc=com",
		Scope:             "sub",
		BindDN:            "cn=panel,dc=example,dc=com",
		UserFilter:        "(objectClass=person)",
		UsernameAttribute: "uid",
		MailAttribute:     "mail",
		Timeout:           10 * time.Second,
		BindPassword:      "s3cret-value",
	}
}

func mutateLDAP(f func(*LDAPConfig)) LDAPConfig {
	cfg := ldapOK()
	f(&cfg)
	return cfg
}

func TestValidateLDAP(t *testing.T) {
	cases := []struct {
		name    string
		cfg     LDAPConfig
		wantErr string
	}{
		{"disabled skips validation", LDAPConfig{}, ""},
		{"valid ldaps deployment", ldapOK(), ""},
		{"host required", mutateLDAP(func(c *LDAPConfig) { c.Host = "" }), "ldap.host is required"},
		{"base dn required", mutateLDAP(func(c *LDAPConfig) { c.BaseDN = "" }), "ldap.baseDN is required"},
		{"bind dn required", mutateLDAP(func(c *LDAPConfig) { c.BindDN = "" }), "ldap.bindDN is required"},
		{"bind password required", mutateLDAP(func(c *LDAPConfig) { c.BindPassword = "" }), "PANEL_LDAP_BIND_PASSWORD is required"},
		{"port lower bound", mutateLDAP(func(c *LDAPConfig) { c.Port = 0 }), "ldap.port must be between 1 and 65535"},
		{"port upper bound", mutateLDAP(func(c *LDAPConfig) { c.Port = 65536 }), "ldap.port must be between 1 and 65535"},
		{"transport must be known", mutateLDAP(func(c *LDAPConfig) { c.Transport = "ftp" }), `ldap.transport must be ldaps, starttls or none`},
		{"plaintext requires explicit opt-in", mutateLDAP(func(c *LDAPConfig) { c.Transport = "none" }), "ldap.transport=none requires ldap.allowInsecure"},
		{"plaintext with opt-in is accepted", mutateLDAP(func(c *LDAPConfig) {
			c.Transport = "none"
			c.AllowInsecure = true
		}), ""},
		{"username attribute shape", mutateLDAP(func(c *LDAPConfig) { c.UsernameAttribute = "1uid" }), "ldap.usernameAttribute must match"},
		{"mail attribute shape", mutateLDAP(func(c *LDAPConfig) { c.MailAttribute = "mail,name" }), "ldap.mailAttribute must match"},
		{"user filter must open", mutateLDAP(func(c *LDAPConfig) { c.UserFilter = "objectClass=person)" }), "ldap.userFilter must be a parenthesised filter"},
		{"user filter must close", mutateLDAP(func(c *LDAPConfig) { c.UserFilter = "(objectClass=person" }), "ldap.userFilter must be a parenthesised filter"},
		{"user filter upper bound", mutateLDAP(func(c *LDAPConfig) { c.UserFilter = "(" + strings.Repeat("x", 520) + ")" }), "ldap.userFilter must not exceed 512"},
		{"user filter must select an attribute", mutateLDAP(func(c *LDAPConfig) { c.UserFilter = "(|(a)(b))" }), ""},
		{"user filter without attribute condition", mutateLDAP(func(c *LDAPConfig) { c.UserFilter = "(&)" }), "ldap.userFilter must reference at least one attribute"},
		{"scope must be known", mutateLDAP(func(c *LDAPConfig) { c.Scope = "children" }), `ldap.scope must be one or sub`},
		{"timeout lower bound", mutateLDAP(func(c *LDAPConfig) { c.Timeout = 0 }), "ldap.timeout must be between 1s and 30s"},
		{"timeout upper bound", mutateLDAP(func(c *LDAPConfig) { c.Timeout = 31 * time.Second }), "ldap.timeout must be between 1s and 30s"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateLDAP(tc.cfg)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validateLDAP() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("validateLDAP() = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestValidateProviders_LDAPImplementable(t *testing.T) {
	// 5b-3 replaces the "not available in this build" answer: a valid LDAP
	// configuration alone must now be accepted, and only the coexistence with
	// OIDC stays forbidden.
	if err := validateProviders(OIDCConfig{}, ldapOK()); err != nil {
		t.Fatalf("validateProviders(ldap only) = %v, want nil", err)
	}
	err := validateProviders(oidcOK(), ldapOK())
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("validateProviders(both) = %v, want the mutual-exclusion error", err)
	}
}

func TestLDAPWarnings(t *testing.T) {
	if got := ldapOK().Warnings(); len(got) != 0 {
		t.Fatalf("warnings for a TLS deployment = %v", got)
	}
	plain := mutateLDAP(func(c *LDAPConfig) {
		c.Transport = "none"
		c.AllowInsecure = true
	})
	if got := plain.Warnings(); len(got) != 1 || !strings.Contains(got[0], "plaintext") {
		t.Fatalf("plaintext warnings = %v, want exactly one mentioning plaintext", got)
	}
	skipVerify := mutateLDAP(func(c *LDAPConfig) { c.InsecureSkipVerify = true })
	if got := skipVerify.Warnings(); len(got) != 1 || !strings.Contains(got[0], "certificate") {
		t.Fatalf("skip-verify warnings = %v, want exactly one mentioning certificate", got)
	}
	both := mutateLDAP(func(c *LDAPConfig) {
		c.Transport = "none"
		c.AllowInsecure = true
		c.InsecureSkipVerify = true
	})
	if got := both.Warnings(); len(got) != 2 {
		t.Fatalf("both warnings = %d, want 2", len(got))
	}
}

func TestLoad_LDAPSection(t *testing.T) {
	t.Setenv("PANEL_AUTH_SECRET", "test-secret-test-secret-test-secret")
	t.Setenv("PANEL_LDAP_BIND_PASSWORD", "env-secret-value")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(`
server: {addr: ":8080"}
log: {level: info, format: json}
auth: {secret: "", accessTTL: 15m, refreshTTL: 168h}
web: {baseURL: "https://panel.example.com"}
oidc:
  enabled: false
ldap:
  enabled: true
  providerName: "Directory"
  host: "ldap.example.com"
  port: 636
  transport: "ldaps"
  baseDN: "dc=example,dc=com"
  bindDN: "cn=panel,dc=example,dc=com"
  bindPassword: "must-be-ignored"
`), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.LDAP.Enabled {
		t.Fatal("ldap.enabled = false, want true")
	}
	if cfg.LDAP.Host != "ldap.example.com" || cfg.LDAP.BaseDN != "dc=example,dc=com" {
		t.Fatalf("ldap section not mapped: %+v", cfg.LDAP)
	}
	// The bind password only ever comes from the environment.
	if cfg.LDAP.BindPassword != "env-secret-value" {
		t.Fatalf("bind password = %q, want the environment value", cfg.LDAP.BindPassword)
	}
	if cfg.LDAP.ProviderName != "Directory" || cfg.LDAP.Transport != "ldaps" ||
		cfg.LDAP.Scope != "sub" || cfg.LDAP.Timeout != 10*time.Second {
		t.Fatalf("defaults not applied: %+v", cfg.LDAP)
	}
}

func TestLoad_LDAPRequiresEnvSecret(t *testing.T) {
	t.Setenv("PANEL_AUTH_SECRET", "test-secret-test-secret-test-secret")
	t.Setenv("PANEL_LDAP_BIND_PASSWORD", "")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(`
server: {addr: ":8080"}
log: {level: info, format: json}
auth: {secret: "", accessTTL: 15m, refreshTTL: 168h}
web: {baseURL: "https://panel.example.com"}
ldap:
  enabled: true
  host: "ldap.example.com"
  baseDN: "dc=example,dc=com"
  bindDN: "cn=panel,dc=example,dc=com"
  bindPassword: "file-copy-must-not-save-us"
`), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "PANEL_LDAP_BIND_PASSWORD") {
		t.Fatalf("Load() error = %v, want a missing-secret error", err)
	}
}
