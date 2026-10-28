package authz_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// TestAccess_BuiltinAdminGainsManagePermission pins the permission rewrite:
// permission sets live in the roles.permissions JSON column, so adding
// access.manage to the catalog alone leaves existing builtin rows behind and
// every established admin keeps getting 403 from the new endpoints. The
// rewrite upgrades the owner row to the full catalog and adds the code to the
// admin row, and running it twice changes nothing.
func TestAccess_BuiltinAdminGainsManagePermission(t *testing.T) {
	st := roleTestStore(t)
	org := model.Organization{Name: "acme"}
	require.NoError(t, st.DB.Create(&org).Error)

	// The permission set as it stood before access.manage existed.
	legacyAdmin := []string{
		authz.PermMemberManage, authz.PermDeviceRead, authz.PermDeviceWrite,
		authz.PermAuditRead, authz.PermAddressBook, authz.PermPolicyWrite, authz.PermApprovalDecide,
	}
	legacyOwner := append([]string{}, legacyAdmin...)
	legacyOwner = append(legacyOwner, authz.PermOrgAdmin, authz.PermRoleManage)

	admin := model.Role{OrganizationID: org.ID, Name: model.RoleKindAdmin, Kind: model.RoleKindAdmin, AuditScope: model.AuditScopeGlobal}
	require.NoError(t, admin.SetPermissions(legacyAdmin))
	require.NoError(t, st.DB.Create(&admin).Error)
	owner := model.Role{OrganizationID: org.ID, Name: model.RoleKindOwner, Kind: model.RoleKindOwner, AuditScope: model.AuditScopeGlobal}
	require.NoError(t, owner.SetPermissions(legacyOwner))
	require.NoError(t, st.DB.Create(&owner).Error)

	require.NoError(t, authz.MigrateAccessPermission(st.DB))
	require.NoError(t, authz.MigrateAccessPermission(st.DB))

	adminRow, err := authz.RoleByKindTx(st.DB, org.ID, model.RoleKindAdmin)
	require.NoError(t, err)
	require.True(t, authz.Has(adminRow.PermissionList(), authz.PermAccessManage))
	require.True(t, authz.Has(adminRow.PermissionList(), authz.PermClientBuildManage))

	require.False(t, authz.Delegable(authz.PermClientBuildManage))

	ownerRow, err := authz.RoleByKindTx(st.DB, org.ID, model.RoleKindOwner)
	require.NoError(t, err)
	require.ElementsMatch(t, authz.AllPermissionCodes(), ownerRow.PermissionList())
}

// TestAccess_PermissionBackfillCoversOrganizationCreatedLater pins the same
// convergence property for permissions: an organization whose builtin rows were
// written before access.manage existed must be upgraded on the next run even
// when a previous run already completed.
func TestAccess_PermissionBackfillCoversOrganizationCreatedLater(t *testing.T) {
	st := roleTestStore(t)
	first := model.Organization{Name: "first"}
	require.NoError(t, st.DB.Create(&first).Error)
	require.NoError(t, authz.MigrateAccessPermission(st.DB))

	late := model.Organization{Name: "late"}
	require.NoError(t, st.DB.Create(&late).Error)
	legacyAdmin := []string{
		authz.PermMemberManage, authz.PermDeviceRead, authz.PermDeviceWrite,
		authz.PermAuditRead, authz.PermAddressBook, authz.PermPolicyWrite, authz.PermApprovalDecide,
	}
	admin := model.Role{OrganizationID: late.ID, Name: model.RoleKindAdmin, Kind: model.RoleKindAdmin, AuditScope: model.AuditScopeGlobal}
	require.NoError(t, admin.SetPermissions(legacyAdmin))
	require.NoError(t, st.DB.Create(&admin).Error)

	require.NoError(t, authz.MigrateAccessPermission(st.DB))

	adminRow, err := authz.RoleByKindTx(st.DB, late.ID, model.RoleKindAdmin)
	require.NoError(t, err)
	require.True(t, authz.Has(adminRow.PermissionList(), authz.PermAccessManage),
		"an organization created after a previous run must still be upgraded")
}

// TestAccess_PermissionBackfillLeavesCustomRolesAlone pins the blast radius:
// only the builtin owner/admin rows are rewritten.
func TestAccess_PermissionBackfillLeavesCustomRolesAlone(t *testing.T) {
	st := roleTestStore(t)
	org := model.Organization{Name: "acme"}
	require.NoError(t, st.DB.Create(&org).Error)

	custom := model.Role{OrganizationID: org.ID, Name: "auditor", Kind: model.RoleKindCustom, AuditScope: model.AuditScopeIndividual}
	require.NoError(t, custom.SetPermissions([]string{authz.PermAuditRead}))
	require.NoError(t, st.DB.Create(&custom).Error)

	require.NoError(t, authz.MigrateAccessPermission(st.DB))

	var row model.Role
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).First(&row, custom.ID).Error)
	require.Equal(t, []string{authz.PermAuditRead}, row.PermissionList())
}
