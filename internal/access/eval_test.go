package access_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/access"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// evalFixture seeds one organization with its access defaults, real builtin
// roles and a writable access service, so evaluation tests exercise the same
// role rows production resolves.
type evalFixture struct {
	st  *store.Store
	svc *access.Service
	org model.Organization
}

func newEvalFixture(t *testing.T) *evalFixture {
	t.Helper()
	st := accessTestStore(t)
	org := model.Organization{Name: "eval-org"}
	require.NoError(t, st.DB.Create(&org).Error)
	require.NoError(t, access.Migrate(st.DB))
	return &evalFixture{
		st:  st,
		svc: access.NewService(st.DB, audit.NewGormAuditor(st.DB), nil),
		org: org,
	}
}

// addMember creates a verified user with a builtin role of the given kind and
// returns the membership. RoleID is set the way MigrateRoles sets it in
// production; evaluation must never guess a role from a zero id.
func (f *evalFixture) addMember(t *testing.T, email, kind string) model.Membership {
	t.Helper()
	user := model.User{Email: email, PasswordHash: "x", EmailVerified: true}
	require.NoError(t, f.st.DB.Create(&user).Error)
	require.NoError(t, authz.NewRoleService(f.st.DB).EnsureBuiltins(f.org.ID))
	role, err := authz.RoleByKindTx(f.st.DB, f.org.ID, kind)
	require.NoError(t, err)
	membership := model.Membership{
		OrganizationID: f.org.ID,
		UserID:         user.ID,
		Role:           kind,
		RoleID:         role.ID,
	}
	require.NoError(t, f.st.DB.Create(&membership).Error)
	return membership
}

func (f *evalFixture) addDevice(t *testing.T, rustdeskID string, disabled bool) model.Device {
	t.Helper()
	device := model.Device{
		OrganizationID: f.org.ID,
		RustdeskID:     rustdeskID,
		Name:           rustdeskID,
		Disabled:       disabled,
	}
	require.NoError(t, f.st.DB.Create(&device).Error)
	return device
}

func (f *evalFixture) userGroup(t *testing.T, name string, memberIDs ...uint) model.UserGroup {
	t.Helper()
	ctx := context.Background()
	group, err := f.svc.CreateUserGroup(ctx, f.org.ID, 1, name)
	require.NoError(t, err)
	_, _, err = f.svc.ReplaceUserGroupMembers(ctx, f.org.ID, 1, group.ID, memberIDs)
	require.NoError(t, err)
	return *group
}

func (f *evalFixture) deviceGroup(t *testing.T, name string, deviceIDs ...uint) model.DeviceGroup {
	t.Helper()
	ctx := context.Background()
	group, err := f.svc.CreateDeviceGroup(ctx, f.org.ID, 1, name)
	require.NoError(t, err)
	_, _, err = f.svc.ReplaceDeviceGroupDevices(ctx, f.org.ID, 1, group.ID, deviceIDs)
	require.NoError(t, err)
	return *group
}

func (f *evalFixture) addRule(t *testing.T, sourceGroupID uint, targetKind string, targetGroupID uint) {
	t.Helper()
	_, err := f.svc.CreateAccessRule(context.Background(), f.org.ID, 1, sourceGroupID, targetKind, targetGroupID)
	require.NoError(t, err)
}

// removeDefaultRule deletes the seeded everyone -> all_devices rule, which is
// how an organization tightens access to explicit group rules (D5).
func (f *evalFixture) removeDefaultRule(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	views, err := f.svc.ListAccessRules(ctx, f.org.ID)
	require.NoError(t, err)
	for _, view := range views {
		if view.Rule.TargetKind == model.AccessTargetKindAllDevices {
			require.NoError(t, f.svc.DeleteAccessRule(ctx, f.org.ID, 1, view.Rule.ID))
		}
	}
}

// TestAccess_MigratedOrgKeepsAllDevicesVisible pins Review Focus #1: an
// organization with only the seeded default rule must keep every device
// visible to an ordinary member, including devices in no device group. The
// membership in the source group is implicit (the everyone group stores no
// member rows), so forgetting the implicit membership breaks this test.
func TestAccess_MigratedOrgKeepsAllDevicesVisible(t *testing.T) {
	f := newEvalFixture(t)
	member := f.addMember(t, "member@example.com", model.RoleKindMember)
	grouped := f.addDevice(t, "100", false)
	f.deviceGroup(t, "workstations", grouped.ID)
	ungrouped := f.addDevice(t, "101", false)

	all, ids, err := f.svc.AllowedDeviceIDs(context.Background(), f.org.ID, member.UserID)
	require.NoError(t, err)
	require.True(t, all, "the seeded everyone -> all_devices rule covers every member")
	require.Empty(t, ids)

	for _, device := range []model.Device{grouped, ungrouped} {
		allowed, err := f.svc.CanAccess(context.Background(), f.org.ID, member.UserID, device.ID)
		require.NoError(t, err)
		require.True(t, allowed, "device %d must stay reachable after migration", device.ID)
	}
}

// TestAccess_UnionOfRules pins D2: rules compose as a union, never as the
// first match. A member of two groups reaches the targets of both rules.
func TestAccess_UnionOfRules(t *testing.T) {
	f := newEvalFixture(t)
	member := f.addMember(t, "union@example.com", model.RoleKindMember)
	f.removeDefaultRule(t)

	groupA := f.userGroup(t, "team-a", member.UserID)
	groupB := f.userGroup(t, "team-b", member.UserID)
	deviceX := f.addDevice(t, "200", false)
	deviceY := f.addDevice(t, "201", false)
	deviceZ := f.addDevice(t, "202", false)
	targetX := f.deviceGroup(t, "servers", deviceX.ID)
	targetY := f.deviceGroup(t, "laptops", deviceY.ID)
	f.deviceGroup(t, "printers", deviceZ.ID)

	f.addRule(t, groupA.ID, model.AccessTargetKindDeviceGroup, targetX.ID)
	f.addRule(t, groupB.ID, model.AccessTargetKindDeviceGroup, targetY.ID)

	all, ids, err := f.svc.AllowedDeviceIDs(context.Background(), f.org.ID, member.UserID)
	require.NoError(t, err)
	require.False(t, all)
	require.ElementsMatch(t, []uint{deviceX.ID, deviceY.ID}, ids, "both rules must contribute their devices")

	for _, want := range []struct {
		device  model.Device
		allowed bool
	}{
		{deviceX, true},
		{deviceY, true},
		{deviceZ, false},
	} {
		allowed, err := f.svc.CanAccess(context.Background(), f.org.ID, member.UserID, want.device.ID)
		require.NoError(t, err)
		require.Equal(t, want.allowed, allowed, "device %s", want.device.RustdeskID)
	}
}

// TestAccess_DisabledDeviceDenied pins D8: a disabled device is unreachable
// even when a rule targets its group, and it never appears in the allowed id
// set that feeds the client peer list.
func TestAccess_DisabledDeviceDenied(t *testing.T) {
	f := newEvalFixture(t)
	member := f.addMember(t, "disabled@example.com", model.RoleKindMember)
	f.removeDefaultRule(t)

	group := f.userGroup(t, "team", member.UserID)
	enabled := f.addDevice(t, "300", false)
	stopped := f.addDevice(t, "301", true)
	target := f.deviceGroup(t, "mixed", enabled.ID, stopped.ID)
	f.addRule(t, group.ID, model.AccessTargetKindDeviceGroup, target.ID)

	all, ids, err := f.svc.AllowedDeviceIDs(context.Background(), f.org.ID, member.UserID)
	require.NoError(t, err)
	require.False(t, all)
	require.Equal(t, []uint{enabled.ID}, ids, "disabled devices must be filtered in the evaluation layer")

	allowed, err := f.svc.CanAccess(context.Background(), f.org.ID, member.UserID, stopped.ID)
	require.NoError(t, err)
	require.False(t, allowed)
}

// TestAccess_DisabledMembershipDenied pins that a disabled membership is
// denied before any rule is considered: the everyone default rule must not
// keep the tenant reachable for a membership an administrator stopped.
func TestAccess_DisabledMembershipDenied(t *testing.T) {
	f := newEvalFixture(t)
	member := f.addMember(t, "stopped@example.com", model.RoleKindMember)
	device := f.addDevice(t, "400", false)
	require.NoError(t, store.ScopedByOrg(f.st.DB, f.org.ID).Model(&model.Membership{}).
		Where("id = ?", member.ID).Update("disabled", true).Error)

	all, ids, err := f.svc.AllowedDeviceIDs(context.Background(), f.org.ID, member.UserID)
	require.NoError(t, err)
	require.False(t, all)
	require.Empty(t, ids)

	allowed, err := f.svc.CanAccess(context.Background(), f.org.ID, member.UserID, device.ID)
	require.NoError(t, err)
	require.False(t, allowed)
}

// TestAccess_AdminBypass pins D7: owner and admin reach every enabled device
// even after the default rule was deleted, while an ordinary member of the
// same tightened organization reaches nothing.
func TestAccess_AdminBypass(t *testing.T) {
	f := newEvalFixture(t)
	owner := f.addMember(t, "owner@example.com", model.RoleKindOwner)
	admin := f.addMember(t, "admin@example.com", model.RoleKindAdmin)
	member := f.addMember(t, "plain@example.com", model.RoleKindMember)
	device := f.addDevice(t, "500", false)
	f.removeDefaultRule(t)

	for _, manager := range []model.Membership{owner, admin} {
		all, ids, err := f.svc.AllowedDeviceIDs(context.Background(), f.org.ID, manager.UserID)
		require.NoError(t, err)
		require.True(t, all, "kind %s must bypass group rules", manager.Role)
		require.Empty(t, ids)

		allowed, err := f.svc.CanAccess(context.Background(), f.org.ID, manager.UserID, device.ID)
		require.NoError(t, err)
		require.True(t, allowed)
	}

	all, ids, err := f.svc.AllowedDeviceIDs(context.Background(), f.org.ID, member.UserID)
	require.NoError(t, err)
	require.False(t, all)
	require.Empty(t, ids)
	allowed, err := f.svc.CanAccess(context.Background(), f.org.ID, member.UserID, device.ID)
	require.NoError(t, err)
	require.False(t, allowed)
}

// TestAccess_UngroupedDeviceNeedsAllDevicesRule pins the 0-sentinel rule: an
// all_devices row stores target_group_id=0 and must be branched on target_kind,
// never treated as device group 0. Devices in no group are covered only by an
// all_devices rule.
func TestAccess_UngroupedDeviceNeedsAllDevicesRule(t *testing.T) {
	f := newEvalFixture(t)
	member := f.addMember(t, "ungrouped@example.com", model.RoleKindMember)
	f.removeDefaultRule(t)

	group := f.userGroup(t, "team", member.UserID)
	grouped := f.addDevice(t, "600", false)
	ungrouped := f.addDevice(t, "601", false)
	target := f.deviceGroup(t, "grouped", grouped.ID)
	f.addRule(t, group.ID, model.AccessTargetKindDeviceGroup, target.ID)

	all, ids, err := f.svc.AllowedDeviceIDs(context.Background(), f.org.ID, member.UserID)
	require.NoError(t, err)
	require.False(t, all)
	require.Equal(t, []uint{grouped.ID}, ids)

	allowed, err := f.svc.CanAccess(context.Background(), f.org.ID, member.UserID, ungrouped.ID)
	require.NoError(t, err)
	require.False(t, allowed, "an ungrouped device is not covered by a device_group rule")

	f.addRule(t, group.ID, model.AccessTargetKindAllDevices, 0)
	all, _, err = f.svc.AllowedDeviceIDs(context.Background(), f.org.ID, member.UserID)
	require.NoError(t, err)
	require.True(t, all)
	allowed, err = f.svc.CanAccess(context.Background(), f.org.ID, member.UserID, ungrouped.ID)
	require.NoError(t, err)
	require.True(t, allowed)
}

// TestAccess_NoMembershipDenied pins fail closed: a user without an active
// membership of the organization reaches nothing, even with the default rule.
func TestAccess_NoMembershipDenied(t *testing.T) {
	f := newEvalFixture(t)
	outsider := model.User{Email: "outsider@example.com", PasswordHash: "x", EmailVerified: true}
	require.NoError(t, f.st.DB.Create(&outsider).Error)
	device := f.addDevice(t, "700", false)

	all, ids, err := f.svc.AllowedDeviceIDs(context.Background(), f.org.ID, outsider.ID)
	require.NoError(t, err)
	require.False(t, all)
	require.Empty(t, ids)
	allowed, err := f.svc.CanAccess(context.Background(), f.org.ID, outsider.ID, device.ID)
	require.NoError(t, err)
	require.False(t, allowed)
}

// TestAccess_UnresolvedRoleFailsClosed pins the role contract: a membership
// whose role_id is zero resolves to no role (authz.Resolve fails closed the
// same way) and must not be guessed into an owner or into the first role row
// of the organization.
func TestAccess_UnresolvedRoleFailsClosed(t *testing.T) {
	f := newEvalFixture(t)
	user := model.User{Email: "norole@example.com", PasswordHash: "x", EmailVerified: true}
	require.NoError(t, f.st.DB.Create(&user).Error)
	require.NoError(t, f.st.DB.Create(&model.Membership{
		OrganizationID: f.org.ID, UserID: user.ID, Role: model.RoleOwner,
	}).Error)
	device := f.addDevice(t, "800", false)

	all, ids, err := f.svc.AllowedDeviceIDs(context.Background(), f.org.ID, user.ID)
	require.NoError(t, err)
	require.False(t, all)
	require.Empty(t, ids)
	allowed, err := f.svc.CanAccess(context.Background(), f.org.ID, user.ID, device.ID)
	require.NoError(t, err)
	require.False(t, allowed)
}

// TestAccess_EvaluationIsTenantScoped pins that another organization's default
// rule never leaks into this tenant's evaluation: org B keeps its
// everyone -> all_devices rule while org A is tightened.
func TestAccess_EvaluationIsTenantScoped(t *testing.T) {
	f := newEvalFixture(t)
	member := f.addMember(t, "tenant@example.com", model.RoleKindMember)
	f.removeDefaultRule(t)

	other := model.Organization{Name: "other-tenant"}
	require.NoError(t, f.st.DB.Create(&other).Error)
	require.NoError(t, access.Migrate(f.st.DB))
	foreignDevice := model.Device{OrganizationID: other.ID, RustdeskID: "900", Name: "foreign"}
	require.NoError(t, f.st.DB.Create(&foreignDevice).Error)

	all, ids, err := f.svc.AllowedDeviceIDs(context.Background(), f.org.ID, member.UserID)
	require.NoError(t, err)
	require.False(t, all, "another tenant's all_devices rule must not grant access here")
	require.Empty(t, ids)

	allowed, err := f.svc.CanAccess(context.Background(), f.org.ID, member.UserID, foreignDevice.ID)
	require.NoError(t, err)
	require.False(t, allowed)
}
