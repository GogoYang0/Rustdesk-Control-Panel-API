package scopetest

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func newDB(t *testing.T) (*gorm.DB, func()) {
	t.Helper()
	s, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: "file::memory:?cache=shared"})
	require.NoError(t, err)
	require.NoError(t, s.DB.AutoMigrate(
		&model.Organization{}, &model.Membership{},
	))
	store.RegisterScopedModel(&model.Membership{})
	return s.DB, func() { _ = s.Close() }
}

// Review Focus #1: two organizations must never see each other's rows.
func TestTenantIsolation_TwoOrgs(t *testing.T) {
	db, cleanup := newDB(t)
	defer cleanup()

	orgA := model.Organization{Name: "org-a"}
	orgB := model.Organization{Name: "org-b"}
	require.NoError(t, db.Create(&orgA).Error)
	require.NoError(t, db.Create(&orgB).Error)

	require.NoError(t, db.Create(&model.Membership{OrganizationID: orgA.ID, UserID: 1, Role: model.RoleOwner}).Error)
	require.NoError(t, db.Create(&model.Membership{OrganizationID: orgB.ID, UserID: 2, Role: model.RoleMember}).Error)

	var fromA []model.Membership
	require.NoError(t, store.ScopedByOrg(db, orgA.ID).Find(&fromA).Error)
	require.Len(t, fromA, 1)
	require.EqualValues(t, 1, fromA[0].UserID, "org A must only see its own member")

	var crossOrg []model.Membership
	require.NoError(t, store.ScopedByOrg(db, orgA.ID).Where("user_id = ?", 2).Find(&crossOrg).Error)
	require.Empty(t, crossOrg, "org A must not see org B rows even with explicit filters")

	var fromB []model.Membership
	require.NoError(t, store.ScopedByOrg(db, orgB.ID).Find(&fromB).Error)
	require.Len(t, fromB, 1)
	require.EqualValues(t, 2, fromB[0].UserID)
}

func TestRequireOrgID(t *testing.T) {
	require.Error(t, store.RequireOrgID(0))
	require.NoError(t, store.RequireOrgID(7))
}

// Every registered scoped model must expose an OrganizationID field.
func TestScopedModels_HaveOrgIDField(t *testing.T) {
	_, cleanup := newDB(t)
	defer cleanup()

	models := store.ScopedModels()
	require.NotEmpty(t, models, "at least one scoped model must be registered")

	for _, m := range models {
		typ := reflect.TypeOf(m).Elem()
		f, ok := typ.FieldByName("OrganizationID")
		require.True(t, ok, "%s must carry an OrganizationID field", typ.Name())
		require.Equal(t, reflect.TypeOf(uint(0)), f.Type)
	}
}

// A zero orgID must fail closed instead of matching organization_id = 0.
func TestScopedByOrg_ZeroOrgFailsClosed(t *testing.T) {
	db, cleanup := newDB(t)
	defer cleanup()

	org := model.Organization{Name: "org-zero"}
	require.NoError(t, db.Create(&org).Error)
	require.NoError(t, db.Create(&model.Membership{OrganizationID: org.ID, UserID: 3, Role: model.RoleMember}).Error)

	var rows []model.Membership
	require.NoError(t, store.ScopedByOrg(db, 0).Find(&rows).Error)
	require.Empty(t, rows, "zero orgID must not return any tenant rows")
}

// Review Focus #1: a caller-side .Or(...) must not escape the tenant condition.
func TestScopedByOrg_OrCannotEscapeTenant(t *testing.T) {
	db, cleanup := newDB(t)
	defer cleanup()

	orgA := model.Organization{Name: "org-a-or"}
	orgB := model.Organization{Name: "org-b-or"}
	require.NoError(t, db.Create(&orgA).Error)
	require.NoError(t, db.Create(&orgB).Error)

	require.NoError(t, db.Create(&model.Membership{OrganizationID: orgA.ID, UserID: 10, Role: model.RoleOwner}).Error)
	require.NoError(t, db.Create(&model.Membership{OrganizationID: orgB.ID, UserID: 20, Role: model.RoleMember}).Error)

	// Org A queries with an OR on user 20 (a user of org B): must return nothing.
	var escaped []model.Membership
	require.NoError(t, store.ScopedByOrg(db, orgA.ID).Or("user_id = ?", 20).Find(&escaped).Error)
	require.Empty(t, escaped, ".Or must not escape the tenant condition")

	// Zero org id must stay empty even with .Or.
	var zero []model.Membership
	require.NoError(t, store.ScopedByOrg(db, 0).Or("user_id = ?", 20).Find(&zero).Error)
	require.Empty(t, zero, ".Or must not escape fail-closed zero org")

	// Top-level OR is rejected for every org (fail closed): silently returning
	// nothing is preferable to a cross-tenant leak. Callers that need
	// disjunction must pass a nested group.
	var orgOr []model.Membership
	require.NoError(t, store.ScopedByOrg(db, orgA.ID).Or("user_id = ?", 10).Find(&orgOr).Error)
	require.Empty(t, orgOr, "top-level OR must fail closed even inside the tenant")
}
