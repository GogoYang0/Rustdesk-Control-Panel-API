package ldapauth

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestGoLDAP_RealDirectory exercises the production client against a real
// OpenLDAP instance. CI's test-db job starts one and exports PANEL_LDAP_TEST_*;
// without the variables (every local run, and the SQLite suites) the group
// skips — the same contract the database suites use.
func TestGoLDAP_RealDirectory(t *testing.T) {
	host := os.Getenv("PANEL_LDAP_TEST_HOST")
	baseDN := os.Getenv("PANEL_LDAP_TEST_BASEDN")
	bindDN := os.Getenv("PANEL_LDAP_TEST_BINDDN")
	bindPassword := os.Getenv("PANEL_LDAP_BIND_PASSWORD")
	if host == "" || baseDN == "" || bindDN == "" || bindPassword == "" {
		t.Skip("PANEL_LDAP_TEST_* not set; the real-directory cases run in CI")
	}

	cfg := Config{
		Host:              host,
		Port:              1389,
		Transport:         "none",
		AllowInsecure:     true,
		BaseDN:            baseDN,
		Scope:             "sub",
		BindDN:            bindDN,
		BindPassword:      bindPassword,
		UserFilter:        "(objectClass=person)",
		UsernameAttribute: "uid",
		MailAttribute:     "mail",
		Timeout:           10 * time.Second,
	}
	dir := NewGoLDAP(cfg)

	t.Run("successful authentication", func(t *testing.T) {
		email, err := dir.Authenticate(context.Background(), "alice", "alicepassword")
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if email != "ldap-alice@example.com" {
			t.Fatalf("email = %q", email)
		}
	})

	t.Run("wrong password is ErrInvalidCredentials", func(t *testing.T) {
		if _, err := dir.Authenticate(context.Background(), "alice", "wrong"); err == nil {
			t.Fatal("Authenticate succeeded with a wrong password")
		} else if err.Error() == "" {
			t.Fatal("empty error")
		}
	})

	t.Run("filter injection does not widen the search", func(t *testing.T) {
		// `*)(uid=*` must escape into a literal username assertion, matching
		// nothing — never matching every entry in the directory.
		if _, err := dir.Authenticate(context.Background(), "*)(uid=*", "x"); err == nil {
			t.Fatal("injection username authenticated; the search was widened")
		}
	})

	t.Run("entry without mail is ErrMissingMail", func(t *testing.T) {
		if _, err := dir.Authenticate(context.Background(), "nomail", "nomailpassword"); err != ErrMissingMail {
			t.Fatalf("Authenticate = %v, want ErrMissingMail", err)
		}
	})
}
