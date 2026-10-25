package authz_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// TestAccess_BuiltinAdminGainsManagePermission pins the one-time backfill:
// permission sets live in the roles.permissions JSON column, so adding
// access.manage to the catalog alone leaves existing builtin rows behind and
// every established admin keeps getting 403 from the new endpoints. The
// backfill must run once, upgrade the owner row to the full catalog and add the
// code to the admin row, leaving custom roles alone.
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

	ownerRow, err := authz.RoleByKindTx(st.DB, org.ID, model.RoleKindOwner)
	require.NoError(t, err)
	require.ElementsMatch(t, authz.AllPermissionCodes(), ownerRow.PermissionList())

	var marks int64
	require.NoError(t, st.DB.Model(&model.MigrationMark{}).
		Where("name = ?", "2026-10-25-m5-access-perm").Count(&marks).Error)
	require.EqualValues(t, 1, marks, "the backfill marker makes the migration one-shot")
}
