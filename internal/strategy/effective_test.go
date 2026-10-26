package strategy_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/strategy"
)

func strategyUpdateEnabled(v bool) strategy.UpdateInput {
	return strategy.UpdateInput{Enabled: &v}
}

func strategyUpdateOptions(v map[string]string) strategy.UpdateInput {
	return strategy.UpdateInput{Options: &v}
}

// pointDeviceAtGroup makes the fixture device a member of the fixture group,
// which is the middle layer of the resolution order.
func (f *fixture) pointDeviceAtGroup(t *testing.T) {
	t.Helper()
	require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).Model(&model.Device{}).
		Where("id = ?", f.device.ID).Update("device_group_id", f.group.ID).Error)
}

func TestEffective_DeviceOverridesGroupAndMember(t *testing.T) {
	f := newFixture(t)
	devS := f.create(t, "Device", map[string]string{"enable-audio": "N"})
	grpS := f.create(t, "Group", map[string]string{"enable-audio": "Y"})
	memS := f.create(t, "Member", map[string]string{"enable-camera": "N"})

	f.pointDeviceAtGroup(t)
	require.NoError(t, f.svc.AssignGroup(context.Background(), f.org.ID, f.user.ID, f.group.ID, &grpS.ID))
	require.NoError(t, f.svc.AssignMember(context.Background(), f.org.ID, f.user.ID, f.user.ID, &memS.ID))
	require.NoError(t, f.svc.AssignDevice(context.Background(), f.org.ID, f.user.ID, f.device.ID, &devS.ID))

	got, err := f.svc.EffectiveForDevice(context.Background(), f.org.ID, f.device.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, devS.ID, got.ID)
}

func TestEffective_GroupOverridesMember(t *testing.T) {
	f := newFixture(t)
	grpS := f.create(t, "Group", map[string]string{"enable-audio": "N"})
	memS := f.create(t, "Member", map[string]string{"enable-camera": "N"})

	f.pointDeviceAtGroup(t)
	require.NoError(t, f.svc.AssignGroup(context.Background(), f.org.ID, f.user.ID, f.group.ID, &grpS.ID))
	require.NoError(t, f.svc.AssignMember(context.Background(), f.org.ID, f.user.ID, f.user.ID, &memS.ID))

	got, err := f.svc.EffectiveForDevice(context.Background(), f.org.ID, f.device.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, grpS.ID, got.ID)
}

func TestEffective_MemberFallbackForOwnedDevice(t *testing.T) {
	f := newFixture(t)
	memS := f.create(t, "Member", map[string]string{"enable-audio": "N"})
	require.NoError(t, f.svc.AssignMember(context.Background(), f.org.ID, f.user.ID, f.user.ID, &memS.ID))

	got, err := f.svc.EffectiveForDevice(context.Background(), f.org.ID, f.device.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, memS.ID, got.ID)
}

// TestEffective_NoOwnerSkipsMemberLayer: an unowned device must not borrow
// somebody else's member-level strategy.
func TestEffective_NoOwnerSkipsMemberLayer(t *testing.T) {
	f := newFixture(t)
	memS := f.create(t, "Member", nil)
	require.NoError(t, f.svc.AssignMember(context.Background(), f.org.ID, f.user.ID, f.user.ID, &memS.ID))
	require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).Model(&model.Device{}).
		Where("id = ?", f.device.ID).Update("owner_user_id", nil).Error)

	got, err := f.svc.EffectiveForDevice(context.Background(), f.org.ID, f.device.ID)
	require.NoError(t, err)
	require.Nil(t, got)
}

func TestEffective_DisabledStrategyIsNone(t *testing.T) {
	f := newFixture(t)
	s := f.create(t, "Baseline", map[string]string{"enable-audio": "N"})
	require.NoError(t, f.svc.AssignDevice(context.Background(), f.org.ID, f.user.ID, f.device.ID, &s.ID))

	disabled := false
	_, err := f.svc.Update(context.Background(), f.org.ID, f.user.ID, s.ID, strategyUpdateEnabled(disabled))
	require.NoError(t, err)

	got, err := f.svc.EffectiveForDevice(context.Background(), f.org.ID, f.device.ID)
	require.NoError(t, err)
	require.Nil(t, got, "a disabled strategy delivers nothing, but the assignment stays")
}

// TestEffective_CrossOrgDeviceIsNone: a device id from another organization
// must not resolve through this organization's scope.
func TestEffective_CrossOrgDeviceIsNone(t *testing.T) {
	f := newFixture(t)
	foreign := model.Device{OrganizationID: f.otherOrg.ID, RustdeskID: "foreign-device", Name: "x"}
	require.NoError(t, store.ScopedByOrg(f.db, f.otherOrg.ID).Create(&foreign).Error)

	got, err := f.svc.EffectiveForDevice(context.Background(), f.org.ID, foreign.ID)
	require.NoError(t, err)
	require.Nil(t, got)
}

// TestEffective_DanglingDeviceStrategyFallsThrough: a strategy id whose row was
// removed out of band must not shadow the group layer.
func TestEffective_DanglingDeviceStrategyFallsThrough(t *testing.T) {
	f := newFixture(t)
	grpS := f.create(t, "Group", nil)
	f.pointDeviceAtGroup(t)
	require.NoError(t, f.svc.AssignGroup(context.Background(), f.org.ID, f.user.ID, f.group.ID, &grpS.ID))

	dangling := uint(999999)
	require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).Model(&model.Device{}).
		Where("id = ?", f.device.ID).Update("strategy_id", dangling).Error)

	got, err := f.svc.EffectiveForDevice(context.Background(), f.org.ID, f.device.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, grpS.ID, got.ID)
}

func TestDelivery_NoStrategyDeliversNothing(t *testing.T) {
	f := newFixture(t)
	d, err := f.svc.DeliveryFor(context.Background(), f.org.ID, f.device.ID, 0)
	require.NoError(t, err)
	require.False(t, d.Deliver)
}

func TestDelivery_DeliversOptionsWithVersion(t *testing.T) {
	f := newFixture(t)
	s := f.create(t, "Baseline", map[string]string{"enable-audio": "N"})
	require.NoError(t, f.svc.AssignDevice(context.Background(), f.org.ID, f.user.ID, f.device.ID, &s.ID))

	d, err := f.svc.DeliveryFor(context.Background(), f.org.ID, f.device.ID, 0)
	require.NoError(t, err)
	require.True(t, d.Deliver)
	require.EqualValues(t, 1, d.Version)
	require.Equal(t, "N", d.Options["enable-audio"])

	// A client that already holds this version gets nothing: the timestamp is
	// the only thing that would change, and re-sending rewrites its config on
	// every heartbeat.
	d, err = f.svc.DeliveryFor(context.Background(), f.org.ID, f.device.ID, 1)
	require.NoError(t, err)
	require.False(t, d.Deliver)

	// A version change re-delivers.
	opts := map[string]string{"enable-audio": "Y"}
	_, err = f.svc.Update(context.Background(), f.org.ID, f.user.ID, s.ID, strategyUpdateOptions(opts))
	require.NoError(t, err)
	d, err = f.svc.DeliveryFor(context.Background(), f.org.ID, f.device.ID, 1)
	require.NoError(t, err)
	require.True(t, d.Deliver)
	require.EqualValues(t, 2, d.Version)
	require.Equal(t, "Y", d.Options["enable-audio"])
}

// TestDelivery_DisabledDeliversNothing pins the kill switch at the delivery
// boundary as well: assigning a disabled strategy must not leak its options.
func TestDelivery_DisabledDeliversNothing(t *testing.T) {
	f := newFixture(t)
	s := f.create(t, "Baseline", map[string]string{"enable-audio": "N"})
	require.NoError(t, f.svc.AssignDevice(context.Background(), f.org.ID, f.user.ID, f.device.ID, &s.ID))
	disabled := false
	_, err := f.svc.Update(context.Background(), f.org.ID, f.user.ID, s.ID, strategyUpdateEnabled(disabled))
	require.NoError(t, err)

	d, err := f.svc.DeliveryFor(context.Background(), f.org.ID, f.device.ID, 0)
	require.NoError(t, err)
	require.False(t, d.Deliver)
}

// TestDelivery_RevalidatesStoredOptions closes the loop on the whitelist: a row
// written behind the service's back (manual UPDATE, older build, future bug)
// must not reach the client, which applies whatever it receives.
func TestDelivery_RevalidatesStoredOptions(t *testing.T) {
	f := newFixture(t)
	s := f.create(t, "Baseline", nil)
	require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).Model(&model.Strategy{}).
		Where("id = ?", s.ID).
		Update("config_options_json", `{"api-server":"evil.example.com"}`).Error)
	require.NoError(t, f.svc.AssignDevice(context.Background(), f.org.ID, f.user.ID, f.device.ID, &s.ID))

	d, err := f.svc.DeliveryFor(context.Background(), f.org.ID, f.device.ID, 0)
	require.ErrorIs(t, err, strategy.ErrUnknownOption)
	require.False(t, d.Deliver)
}
