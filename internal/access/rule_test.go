package access_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/access"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// ruleFixture seeds an organization with the access defaults, a custom user
// group, and a device group, all belonging to the same tenant.
func ruleFixture(t *testing.T) (*store.Store, *access.Service, model.Organization, model.UserGroup, model.DeviceGroup) {
	t.Helper()
	ctx := context.Background()
	st, svc, org, _ := newGroupFixture(t)
	userGroup, err := svc.CreateUserGroup(ctx, org.ID, 1, "Ops")
	require.NoError(t, err)
	deviceGroup, err := svc.CreateDeviceGroup(ctx, org.ID, 1, "Servers")
	require.NoError(t, err)
	return st, svc, org, *userGroup, *deviceGroup
}

// TestAccess_CreateRuleValidatesSameOrg pins the validation gate: source and
// target must live in the caller's organization, and the target id must agree
// with the target kind.
func TestAccess_CreateRuleValidatesSameOrg(t *testing.T) {
	ctx := context.Background()
	st, svc, org, userGroup, deviceGroup := ruleFixture(t)

	other := model.Organization{Name: "rule-other-org"}
	require.NoError(t, st.DB.Create(&other).Error)
	foreignUser, err := svc.CreateUserGroup(ctx, other.ID, 1, "Foreign")
	require.NoError(t, err)
	foreignDevice, err := svc.CreateDeviceGroup(ctx, other.ID, 1, "Foreign devices")
	require.NoError(t, err)

	_, err = svc.CreateAccessRule(ctx, org.ID, 1, foreignUser.ID, model.AccessTargetKindAllDevices, 0)
	require.ErrorIs(t, err, access.ErrInvalidRule)

	_, err = svc.CreateAccessRule(ctx, org.ID, 1, userGroup.ID, model.AccessTargetKindDeviceGroup, foreignDevice.ID)
	require.ErrorIs(t, err, access.ErrInvalidRule)

	_, err = svc.CreateAccessRule(ctx, org.ID, 1, userGroup.ID, "unknown_kind", 0)
	require.ErrorIs(t, err, access.ErrInvalidRule)

	_, err = svc.CreateAccessRule(ctx, org.ID, 1, userGroup.ID, model.AccessTargetKindAllDevices, deviceGroup.ID)
	require.ErrorIs(t, err, access.ErrInvalidRule, "all_devices must carry the 0 sentinel")

	_, err = svc.CreateAccessRule(ctx, org.ID, 1, userGroup.ID, model.AccessTargetKindDeviceGroup, 0)
	require.ErrorIs(t, err, access.ErrInvalidRule, "device_group must carry a real group id")

	var rules int64
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).
		Model(&model.AccessRule{}).Where("source_group_id = ?", userGroup.ID).Count(&rules).Error)
	require.Zero(t, rules, "no rejected request may create a rule")
}

// TestAccess_CreateRuleUnique pins the unique tuple: the same allow rule can
// exist only once per organization, while a different source is a new rule.
func TestAccess_CreateRuleUnique(t *testing.T) {
	ctx := context.Background()
	_, svc, org, userGroup, deviceGroup := ruleFixture(t)

	rule, err := svc.CreateAccessRule(ctx, org.ID, 1, userGroup.ID, model.AccessTargetKindDeviceGroup, deviceGroup.ID)
	require.NoError(t, err)
	require.Equal(t, userGroup.ID, rule.SourceGroupID)
	require.Equal(t, deviceGroup.ID, rule.TargetGroupID)

	_, err = svc.CreateAccessRule(ctx, org.ID, 1, userGroup.ID, model.AccessTargetKindDeviceGroup, deviceGroup.ID)
	require.ErrorIs(t, err, access.ErrRuleExists)

	_, err = svc.CreateAccessRule(ctx, org.ID, 1, userGroup.ID, model.AccessTargetKindAllDevices, 0)
	require.NoError(t, err, "a different target kind is a different rule")
}

// TestAccess_DeleteDefaultRule pins the tightening path: the seeded
// everyone -> all_devices rule is a normal deletable row.
func TestAccess_DeleteDefaultRule(t *testing.T) {
	ctx := context.Background()
	st, svc, org, _, _ := ruleFixture(t)

	views, err := svc.ListAccessRules(ctx, org.ID)
	require.NoError(t, err)
	require.Len(t, views, 1)
	require.Equal(t, model.AccessTargetKindAllDevices, views[0].Rule.TargetKind)
	require.Equal(t, model.EveryoneGroupName, views[0].SourceGroupName, "the view carries the source group name")
	require.Empty(t, views[0].TargetGroupName, "all_devices has no target group name")

	defaultRuleID := views[0].Rule.ID
	require.NoError(t, svc.DeleteAccessRule(ctx, org.ID, 1, defaultRuleID))

	views, err = svc.ListAccessRules(ctx, org.ID)
	require.NoError(t, err)
	require.Empty(t, views, "after deleting the default rule the organization has no access at all")

	require.ErrorIs(t, svc.DeleteAccessRule(ctx, org.ID, 1, defaultRuleID), access.ErrRuleNotFound)

	// The groups themselves survive rule deletion.
	var groups int64
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).Model(&model.UserGroup{}).Count(&groups).Error)
	require.EqualValues(t, 2, groups)
}

// TestAccess_RuleListViewNames pins the list payload: the device-group target
// name is resolved for device_group rules.
func TestAccess_RuleListViewNames(t *testing.T) {
	ctx := context.Background()
	_, svc, org, userGroup, deviceGroup := ruleFixture(t)

	_, err := svc.CreateAccessRule(ctx, org.ID, 1, userGroup.ID, model.AccessTargetKindDeviceGroup, deviceGroup.ID)
	require.NoError(t, err)

	views, err := svc.ListAccessRules(ctx, org.ID)
	require.NoError(t, err)
	require.Len(t, views, 2)
	byKind := map[string]access.RuleView{}
	for _, view := range views {
		byKind[view.Rule.TargetKind] = view
	}
	require.Equal(t, "Ops", byKind[model.AccessTargetKindDeviceGroup].SourceGroupName)
	require.Equal(t, "Servers", byKind[model.AccessTargetKindDeviceGroup].TargetGroupName)
}

// TestAccess_DefaultRuleDeletionSurvivesRestart pins the tightening contract:
// deleting the seeded everyone -> all_devices rule must survive process
// restarts. Re-seeding it on boot would silently hand every member the whole
// device list back, with no audit entry the administrator could notice.
func TestAccess_DefaultRuleDeletionSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	st, svc, org, _, _ := ruleFixture(t)

	views, err := svc.ListAccessRules(ctx, org.ID)
	require.NoError(t, err)
	require.Len(t, views, 1)

	require.NoError(t, svc.DeleteAccessRule(ctx, org.ID, 1, views[0].Rule.ID))

	// A restart runs the same convergence entrypoint the server uses.
	require.NoError(t, access.Migrate(st.DB))

	views, err = svc.ListAccessRules(ctx, org.ID)
	require.NoError(t, err)
	require.Empty(t, views, "the deleted default rule must not be re-seeded on restart")

	// The everyone group itself is still there (it is never deletable).
	everyone := everyoneGroup(t, st, org.ID)
	require.Equal(t, model.UserGroupKindEveryone, everyone.Kind)
}

// TestAccess_RuleWriteFailsClosed pins the audit contract for rules.
func TestAccess_RuleWriteFailsClosed(t *testing.T) {
	ctx := context.Background()
	st, _, org, userGroup, deviceGroup := ruleFixture(t)
	unaudited := access.NewService(st.DB, nil, nil)

	_, err := unaudited.CreateAccessRule(ctx, org.ID, 1, userGroup.ID, model.AccessTargetKindDeviceGroup, deviceGroup.ID)
	require.ErrorIs(t, err, access.ErrAuditUnavailable)
	require.ErrorIs(t, unaudited.DeleteAccessRule(ctx, org.ID, 1, 1), access.ErrAuditUnavailable)

	var count int64
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).Model(&model.AccessRule{}).Count(&count).Error)
	require.EqualValues(t, 1, count, "only the seeded default rule exists")
}
