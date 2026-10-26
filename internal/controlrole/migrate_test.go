package controlrole_test

import (
	"encoding/json"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/controlrole"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

var migrateSeq atomic.Int64

// openMigrateStore mirrors the session harness: CI exports TEST_POSTGRES_DSN /
// TEST_MYSQL_DSN and the migration must run on those dialects too.
func openMigrateStore(t *testing.T) *store.Store {
	t.Helper()
	switch {
	case os.Getenv("TEST_POSTGRES_DSN") != "":
		s, err := store.Open(config.DatabaseConfig{Driver: "postgres", DSN: os.Getenv("TEST_POSTGRES_DSN")})
		require.NoError(t, err)
		return s
	case os.Getenv("TEST_MYSQL_DSN") != "":
		s, err := store.Open(config.DatabaseConfig{Driver: "mysql", DSN: os.Getenv("TEST_MYSQL_DSN")})
		require.NoError(t, err)
		return s
	}
	s, err := store.Open(config.DatabaseConfig{
		Driver: "sqlite",
		DSN:    fmt.Sprintf("file:controlrole_migrate_%d?mode=memory&cache=shared", migrateSeq.Add(1)),
	})
	require.NoError(t, err)
	return s
}

func fixedClock() time.Time { return time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC) }

func TestMigrate_CreatesDefaultRolePerOrganization(t *testing.T) {
	s := openMigrateStore(t)
	t.Cleanup(func() { _ = s.Close() })
	require.NoError(t, s.DB.AutoMigrate(&model.Organization{}, &model.ControlRole{}))

	orgs := make([]model.Organization, 0, 2)
	for _, name := range []string{"acme", "globex"} {
		org := model.Organization{Name: name}
		require.NoError(t, s.DB.Create(&org).Error)
		orgs = append(orgs, org)
	}

	// Twice on purpose: the marker-free seed must be idempotent, because every
	// startup runs it.
	require.NoError(t, controlrole.Migrate(s.DB, fixedClock))
	require.NoError(t, controlrole.Migrate(s.DB, fixedClock))

	// Scope the read to this test's organizations: the CI test-db job shares
	// one database, so an unscoped count would include every other test's seed.
	ids := []uint{orgs[0].ID, orgs[1].ID}
	var rows []model.ControlRole
	require.NoError(t, store.WithoutTenantScope(s.DB).
		Where("organization_id IN ?", ids).Order("organization_id").Find(&rows).Error)
	require.Len(t, rows, 2)
	for _, r := range rows {
		require.Equal(t, model.KindControlRoleDefault, r.Kind)
		require.Equal(t, controlrole.DefaultRoleName, r.Name)
	}
}

func TestMigrate_DefaultRolePermissionsAreUseClient(t *testing.T) {
	s := openMigrateStore(t)
	t.Cleanup(func() { _ = s.Close() })
	require.NoError(t, s.DB.AutoMigrate(&model.Organization{}, &model.ControlRole{}))
	org := model.Organization{Name: "acme"}
	require.NoError(t, s.DB.Create(&org).Error)
	require.NoError(t, controlrole.Migrate(s.DB, fixedClock))

	var role model.ControlRole
	require.NoError(t, store.ScopedByOrg(s.DB, org.ID).First(&role).Error)

	var stored map[string]string
	require.NoError(t, json.Unmarshal([]byte(role.PermissionsJSON), &stored))
	require.Len(t, stored, len(controlrole.Keys()))
	for _, key := range controlrole.Keys() {
		require.Equal(t, string(controlrole.StateUseClient), stored[key], "key %s", key)
	}
}
