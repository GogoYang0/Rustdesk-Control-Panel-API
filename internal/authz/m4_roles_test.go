package authz_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func roleTestStore(t *testing.T) *store.Store {
	t.Helper()
	dsn := fmt.Sprintf("file:roles_%d?mode=memory&cache=shared", time.Now().UnixNano())
	st, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	require.NoError(t, st.DB.AutoMigrate(
		&model.User{}, &model.Organization{}, &model.Membership{}, &model.Role{}, &model.MigrationMark{},
	))
	return st
}

func TestEnsureBuiltins_SeedsThreeRolesAndIsIdempotent(t *testing.T) {
	st := roleTestStore(t)
	org := model.Organization{Name: "acme"}
	require.NoError(t, st.DB.Create(&org).Error)

	svc := authz.NewRoleService(st.DB)
	require.NoError(t, svc.EnsureBuiltins(org.ID))
	require.NoError(t, svc.EnsureBuiltins(org.ID))

	var roles []model.Role
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).Order("kind").Find(&roles).Error)
	require.Len(t, roles, 3)
	byKind := map[string]model.Role{}
	for _, r := range roles {
		byKind[r.Kind] = r
	}
	require.Equal(t, "owner", byKind[model.RoleKindOwner].Name)
	require.ElementsMatch(t, authz.AllPermissionCodes(), byKind[model.RoleKindOwner].PermissionList())
	require.NotContains(t, byKind[model.RoleKindAdmin].PermissionList(), authz.PermOrgAdmin)
	require.Equal(t, []string{authz.PermDeviceRead}, byKind[model.RoleKindMember].PermissionList())
}

func TestRoleMigration_BackfillsLegacyRoleStrings(t *testing.T) {
	st := roleTestStore(t)
	org := model.Organization{Name: "acme"}
	require.NoError(t, st.DB.Create(&org).Error)
	user := model.User{Email: "a@example.com", PasswordHash: "x", EmailVerified: true}
	require.NoError(t, st.DB.Create(&user).Error)
	require.NoError(t, st.DB.Create(&model.Membership{
		OrganizationID: org.ID, UserID: user.ID, Role: model.RoleAdmin,
	}).Error)

	require.NoError(t, authz.MigrateRoles(st.DB))

	var m model.Membership
	require.NoError(t, store.WithoutTenantScope(st.DB).First(&m).Error)
	require.NotZero(t, m.RoleID)
	var role model.Role
	require.NoError(t, store.WithoutTenantScope(st.DB).First(&role, m.RoleID).Error)
	require.Equal(t, model.RoleKindAdmin, role.Kind)

	// The marker makes the migration one-shot: a second call is a no-op.
	require.NoError(t, authz.MigrateRoles(st.DB))
	var marks int64
	require.NoError(t, st.DB.Model(&model.MigrationMark{}).Count(&marks).Error)
	require.EqualValues(t, 1, marks)
}

func TestRoleMigration_UnknownRoleFailsClosed(t *testing.T) {
	st := roleTestStore(t)
	org := model.Organization{Name: "acme"}
	require.NoError(t, st.DB.Create(&org).Error)
	user := model.User{Email: "b@example.com", PasswordHash: "x", EmailVerified: true}
	require.NoError(t, st.DB.Create(&user).Error)
	require.NoError(t, st.DB.Create(&model.Membership{
		OrganizationID: org.ID, UserID: user.ID, Role: "intern",
	}).Error)

	err := authz.MigrateRoles(st.DB)
	require.Error(t, err)
	require.Contains(t, err.Error(), "intern")
}

func TestPermissionSet_MatchesBuiltinKinds(t *testing.T) {
	require.True(t, authz.Has(authz.BuiltinPermissions(model.RoleKindOwner), authz.PermOrgAdmin))
	require.False(t, authz.Has(authz.BuiltinPermissions(model.RoleKindAdmin), authz.PermOrgAdmin))
	require.False(t, authz.Has(authz.BuiltinPermissions(model.RoleKindAdmin), authz.PermRoleManage))
	require.False(t, authz.Has(authz.BuiltinPermissions(model.RoleKindMember), authz.PermMemberManage))
	require.False(t, authz.Has(authz.BuiltinPermissions(model.RoleKindMember), "org.nuke"))
	require.False(t, authz.Delegable(authz.PermOrgAdmin))
	require.False(t, authz.Delegable(authz.PermRoleManage))
	require.True(t, authz.Delegable(authz.PermAuditRead))
}
