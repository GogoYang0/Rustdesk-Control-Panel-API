package authz_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// TestMigrateDropLegacyRole_RemovesColumnAndIsIdempotent covers an upgraded
// database: AutoMigrate no longer creates memberships.role once the field is
// gone from the model, so the legacy shape is recreated explicitly here.
func TestMigrateDropLegacyRole_RemovesColumnAndIsIdempotent(t *testing.T) {
	st := roleTestStore(t)
	require.NoError(t, st.DB.Exec("ALTER TABLE memberships ADD COLUMN role varchar(16) NOT NULL DEFAULT ''").Error)
	require.True(t, st.DB.Migrator().HasColumn(&model.Membership{}, "role"))

	require.NoError(t, authz.MigrateDropLegacyRole(st.DB))
	require.False(t, st.DB.Migrator().HasColumn(&model.Membership{}, "role"),
		"the legacy column must be gone after the migration")

	require.NoError(t, authz.MigrateDropLegacyRole(st.DB), "a second boot must be a no-op")
}

func TestMigrateDropLegacyRole_RecordsMarkOnFreshDatabase(t *testing.T) {
	st := roleTestStore(t)

	require.NoError(t, authz.MigrateDropLegacyRole(st.DB))

	var mark model.MigrationMark
	require.NoError(t, st.DB.Where("name = ?", authz.DropLegacyRoleMark).First(&mark).Error)
}

// TestMigrateRoles_SkipsLegacyMappingWhenColumnIsGone pins the ordering
// contract: after the drop migration the backfill can no longer read
// memberships.role, and it must still finish (seeding builtins, writing its own
// marker) instead of failing the boot.
func TestMigrateRoles_SkipsLegacyMappingWhenColumnIsGone(t *testing.T) {
	st := roleTestStore(t)
	org := model.Organization{Name: "acme"}
	require.NoError(t, st.DB.Create(&org).Error)

	require.NoError(t, st.DB.Exec("ALTER TABLE memberships ADD COLUMN role varchar(16) NOT NULL DEFAULT ''").Error)
	require.NoError(t, st.DB.Exec("INSERT INTO memberships (organization_id, user_id, role_id, role, disabled) VALUES (?, ?, 0, 'member', 0)", org.ID, 42).Error)
	require.NoError(t, authz.MigrateDropLegacyRole(st.DB))

	require.NoError(t, authz.MigrateRoles(st.DB))

	// The builtins are still seeded — that part of the migration must not be
	// skipped — and the migration records its own marker.
	role, err := authz.RoleByKindTx(st.DB, org.ID, model.RoleKindMember)
	require.NoError(t, err)
	require.Equal(t, model.RoleKindMember, role.Kind)
	var mark model.MigrationMark
	require.NoError(t, st.DB.Where("name = ?", "2026-10-24-m4-roles").First(&mark).Error)

	// The unmapped membership keeps role_id = 0, which authorizes nothing: the
	// drop must follow the backfill, and main.go runs them in that order.
	var m model.Membership
	require.NoError(t, store.WithoutTenantScope(st.DB).
		Where("organization_id = ? AND user_id = ?", org.ID, 42).First(&m).Error)
	require.Zero(t, m.RoleID, "a membership the backfill never reached authorizes nothing")
}
