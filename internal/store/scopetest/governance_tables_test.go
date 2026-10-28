package scopetest

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm/schema"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// TestScopedModels_CoverSessionGovernanceTables pins tenant coverage for the
// M3 session-governance tables. A table that is not registered here is not
// scoped: reads would return every organization's rows and writes would land in
// whichever organization the caller names (C13/C14).
func TestScopedModels_CoverSessionGovernanceTables(t *testing.T) {
	// Registration happens in store.Open; without it the set is empty and the
	// test would fail for the wrong reason.
	_, cleanup := newDB(t)
	defer cleanup()

	registered := map[string]bool{}
	for _, m := range store.ScopedModels() {
		if tn, ok := m.(interface{ TableName() string }); ok {
			registered[tn.TableName()] = true
			continue
		}
		s, err := schema.Parse(m, &sync.Map{}, schema.NamingStrategy{})
		require.NoError(t, err)
		registered[s.Table] = true
	}

	for _, table := range []string{
		"sessions",
		"session_events",
		"tickets",
		"policies",
		"approvals",
		"alerts",
	} {
		require.True(t, registered[table],
			"%s must be registered as a tenant-scoped model, otherwise tenant isolation does not apply to it", table)
	}
}

// TestScopedModels_CoverAccessControlTables pins tenant coverage for the M5
// access-control tables. A table missing from the registry would let group,
// member and rule queries cross organizations.
func TestScopedModels_CoverAccessControlTables(t *testing.T) {
	_, cleanup := newDB(t)
	defer cleanup()

	registered := map[string]bool{}
	for _, m := range store.ScopedModels() {
		if tn, ok := m.(interface{ TableName() string }); ok {
			registered[tn.TableName()] = true
			continue
		}
		s, err := schema.Parse(m, &sync.Map{}, schema.NamingStrategy{})
		require.NoError(t, err)
		registered[s.Table] = true
	}

	for _, table := range []string{
		"user_groups",
		"user_group_members",
		"device_groups",
		"access_rules",
		"control_roles",
		"connection_logs",
		"file_logs",
		"strategies",
		"device_disconnects",
	} {
		require.True(t, registered[table],
			"%s must be registered as a tenant-scoped model, otherwise tenant isolation does not apply to it", table)
	}
}
