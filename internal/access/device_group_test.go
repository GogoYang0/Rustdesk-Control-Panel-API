package access_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/access"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func seedDevice(t *testing.T, st *store.Store, orgID uint, rustdeskID string) model.Device {
	t.Helper()
	device := model.Device{OrganizationID: orgID, RustdeskID: rustdeskID, Name: rustdeskID}
	require.NoError(t, st.DB.Create(&device).Error)
	return device
}

func reloadDevice(t *testing.T, st *store.Store, orgID, deviceID uint) model.Device {
	t.Helper()
	var device model.Device
	require.NoError(t, store.ScopedByOrg(st.DB, orgID).First(&device, deviceID).Error)
	return device
}

// TestAccess_DeviceMoveClearsPreviousGroup pins the one-group rule: moving a
// device into another device group rewrites its single reference, so the old
// group's rules stop applying immediately.
func TestAccess_DeviceMoveClearsPreviousGroup(t *testing.T) {
	ctx := context.Background()
	st, svc, org, _ := newGroupFixture(t)
	device := seedDevice(t, st, org.ID, "100000001")

	groupA, err := svc.CreateDeviceGroup(ctx, org.ID, 1, "  Servers  ")
	require.NoError(t, err)
	require.Equal(t, "Servers", groupA.Name)
	groupB, err := svc.CreateDeviceGroup(ctx, org.ID, 1, "Laptops")
	require.NoError(t, err)

	_, err = svc.CreateDeviceGroup(ctx, org.ID, 1, "servers")
	require.ErrorIs(t, err, access.ErrDeviceGroupNameTaken)

	added, removed, err := svc.ReplaceDeviceGroupDevices(ctx, org.ID, 1, groupA.ID, []uint{device.ID})
	require.NoError(t, err)
	require.Equal(t, 1, added)
	require.Zero(t, removed)
	require.NotNil(t, reloadDevice(t, st, org.ID, device.ID).DeviceGroupID)
	require.Equal(t, groupA.ID, *reloadDevice(t, st, org.ID, device.ID).DeviceGroupID)

	added, removed, err = svc.ReplaceDeviceGroupDevices(ctx, org.ID, 1, groupB.ID, []uint{device.ID})
	require.NoError(t, err)
	require.Equal(t, 1, added, "the device is newly placed into group B")
	require.Zero(t, removed, "group B did not hold the device before")
	require.Equal(t, groupB.ID, *reloadDevice(t, st, org.ID, device.ID).DeviceGroupID)

	views, err := svc.ListDeviceGroups(ctx, org.ID)
	require.NoError(t, err)
	byID := map[uint]access.DeviceGroupView{}
	for _, view := range views {
		byID[view.Group.ID] = view
	}
	require.Empty(t, byID[groupA.ID].DeviceIDs, "moving the device must clear the previous group")
	require.Equal(t, []uint{device.ID}, byID[groupB.ID].DeviceIDs)

	// The move audit must record where each device came from: the previous
	// reference is the only surviving trace once it has been overwritten.
	var audits []model.AuditLog
	require.NoError(t, store.WithoutTenantScope(st.DB).Model(&model.AuditLog{}).
		Where("action = ? AND target_id = ?", "access.device_group.devices", fmt.Sprint(groupB.ID)).
		Find(&audits).Error)
	require.Len(t, audits, 1)
	require.Contains(t, audits[0].Detail, `"moved_from"`)
	require.Contains(t, audits[0].Detail, `"`+fmt.Sprint(device.ID)+`"`)
}

// TestAccess_DeleteDeviceGroupClearsDevicesAndRules pins deletion: devices
// return to ungrouped (the column is cleared) and every rule targeting the
// group is cascaded with its own audit entry.
func TestAccess_DeleteDeviceGroupClearsDevicesAndRules(t *testing.T) {
	ctx := context.Background()
	st, svc, org, _ := newGroupFixture(t)
	device := seedDevice(t, st, org.ID, "100000002")

	group, err := svc.CreateDeviceGroup(ctx, org.ID, 1, "Servers")
	require.NoError(t, err)
	_, _, err = svc.ReplaceDeviceGroupDevices(ctx, org.ID, 1, group.ID, []uint{device.ID})
	require.NoError(t, err)

	everyone := everyoneGroup(t, st, org.ID)
	rule := model.AccessRule{
		OrganizationID: org.ID, SourceGroupID: everyone.ID,
		TargetKind: model.AccessTargetKindDeviceGroup, TargetGroupID: group.ID,
	}
	require.NoError(t, st.DB.Create(&rule).Error)

	removedRules, ungrouped, err := svc.DeleteDeviceGroup(ctx, org.ID, 1, group.ID)
	require.NoError(t, err)
	require.Equal(t, 1, removedRules)
	require.Equal(t, 1, ungrouped)

	require.Nil(t, reloadDevice(t, st, org.ID, device.ID).DeviceGroupID, "deleting the group must clear the device reference")

	var rules int64
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).
		Model(&model.AccessRule{}).Where("target_kind = ? AND target_group_id = ?",
		model.AccessTargetKindDeviceGroup, group.ID).Count(&rules).Error)
	require.Zero(t, rules)

	var audits []model.AuditLog
	require.NoError(t, store.WithoutTenantScope(st.DB).Model(&model.AuditLog{}).
		Where("action = ?", "access.rule.delete").Find(&audits).Error)
	require.Len(t, audits, 1)
	require.Contains(t, audits[0].Detail, `"target_group_id"`)
}

// TestAccess_ReplaceDevicesRejectsForeignDevice pins the all-or-nothing device
// rule: an id from another organization rejects the whole request.
func TestAccess_ReplaceDevicesRejectsForeignDevice(t *testing.T) {
	ctx := context.Background()
	st, svc, org, _ := newGroupFixture(t)
	own := seedDevice(t, st, org.ID, "100000003")

	other := model.Organization{Name: "other-device-org"}
	require.NoError(t, st.DB.Create(&other).Error)
	foreign := seedDevice(t, st, other.ID, "200000003")

	group, err := svc.CreateDeviceGroup(ctx, org.ID, 1, "Servers")
	require.NoError(t, err)

	_, _, err = svc.ReplaceDeviceGroupDevices(ctx, org.ID, 1, group.ID, []uint{own.ID, foreign.ID})
	require.ErrorIs(t, err, access.ErrInvalidDevice)

	_, _, err = svc.ReplaceDeviceGroupDevices(ctx, org.ID, 1, group.ID, []uint{own.ID, 999999})
	require.ErrorIs(t, err, access.ErrInvalidDevice)

	require.Nil(t, reloadDevice(t, st, org.ID, own.ID).DeviceGroupID,
		"a rejected request must not assign the valid ids")
}

// TestAccess_DeviceGroupCrossTenantNotFound pins tenant scoping of group ids.
func TestAccess_DeviceGroupCrossTenantNotFound(t *testing.T) {
	ctx := context.Background()
	st, svc, orgA, _ := newGroupFixture(t)
	orgB := model.Organization{Name: "other-dg-org"}
	require.NoError(t, st.DB.Create(&orgB).Error)
	groupB, err := svc.CreateDeviceGroup(ctx, orgB.ID, 1, "B group")
	require.NoError(t, err)

	_, err = svc.RenameDeviceGroup(ctx, orgA.ID, 1, groupB.ID, "hijacked")
	require.ErrorIs(t, err, access.ErrDeviceGroupNotFound)
	_, _, err = svc.DeleteDeviceGroup(ctx, orgA.ID, 1, groupB.ID)
	require.ErrorIs(t, err, access.ErrDeviceGroupNotFound)
	_, _, err = svc.ReplaceDeviceGroupDevices(ctx, orgA.ID, 1, groupB.ID, nil)
	require.ErrorIs(t, err, access.ErrDeviceGroupNotFound)
}

// TestAccess_DeviceGroupWriteFailsClosed pins the audit contract for device
// groups: without a transactional recorder nothing is written.
func TestAccess_DeviceGroupWriteFailsClosed(t *testing.T) {
	ctx := context.Background()
	st, _, org, _ := newGroupFixture(t)
	unaudited := access.NewService(st.DB, nil, nil)

	_, err := unaudited.CreateDeviceGroup(ctx, org.ID, 1, "Servers")
	require.ErrorIs(t, err, access.ErrAuditUnavailable)

	var count int64
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).
		Model(&model.DeviceGroup{}).Count(&count).Error)
	require.Zero(t, count)
}
