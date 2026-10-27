package model

import (
	"sync"
	"testing"

	"gorm.io/gorm/schema"
)

// TestPersistentModels_IncludesIdentityTables pins the two OIDC tables into the
// AutoMigrate registry. A model that only exists in code is missing in
// production exactly the way Strategy/DeviceDisconnect were in wave 4.
func TestPersistentModels_IncludesIdentityTables(t *testing.T) {
	got := map[string]bool{}
	for _, m := range PersistentModels() {
		got[tableNameOf(t, m)] = true
	}
	for _, want := range []string{"user_identities", "external_login_flows"} {
		if !got[want] {
			t.Fatalf("%s missing from PersistentModels()", want)
		}
	}
}

// TestIdentityTableNames pins the names the runbooks and SQL snippets use;
// GORM's pluralizer would otherwise render ExternalLoginFlow as
// external_login_flows while UserIdentity stays user_identities — one right by
// accident is worse than two explicit names.
func TestIdentityTableNames(t *testing.T) {
	if got := tableNameOf(t, &UserIdentity{}); got != "user_identities" {
		t.Fatalf("UserIdentity table = %q", got)
	}
	if got := tableNameOf(t, &ExternalLoginFlow{}); got != "external_login_flows" {
		t.Fatalf("ExternalLoginFlow table = %q", got)
	}
}

// TestExternalLoginFlow_TicketColumns pins the columns that make a ticket
// single-use: state and ticket are consumed at different moments, so one
// ConsumedAt cannot express both. Losing these columns silently turns a ticket
// into a reusable token.
func TestExternalLoginFlow_TicketColumns(t *testing.T) {
	s, err := schema.Parse(&ExternalLoginFlow{}, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	for _, name := range []string{"State", "Nonce", "PKCEVerifier", "TicketHash", "TicketExpiresAt", "TicketConsumedAt", "ExpiresAt", "ConsumedAt"} {
		if s.LookUpField(name) == nil {
			t.Fatalf("ExternalLoginFlow is missing field %s", name)
		}
	}
}

// TestUserIdentity_UniqueIndexes pins both uniqueness rules: one binding per
// (provider, issuer, subject), and one per (user, provider, issuer). Dropping
// either lets a replayed subject bind two accounts or one account bind twice.
func TestUserIdentity_UniqueIndexes(t *testing.T) {
	s, err := schema.Parse(&UserIdentity{}, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	bySubject, byUser := false, false
	for _, idx := range s.ParseIndexes() {
		cols := map[string]bool{}
		for _, f := range idx.Fields {
			cols[f.DBName] = true
		}
		switch {
		case cols["provider"] && cols["issuer"] && cols["subject"]:
			bySubject = true
		case cols["user_id"] && cols["provider"] && cols["issuer"]:
			byUser = true
		}
	}
	if !bySubject || !byUser {
		t.Fatalf("missing unique index: provider+issuer+subject=%v user+provider+issuer=%v", bySubject, byUser)
	}
}
