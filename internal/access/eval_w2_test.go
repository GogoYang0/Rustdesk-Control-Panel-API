package access_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// ownDevice marks a device as owned by one member.
func (f *evalFixture) ownDevice(t *testing.T, device model.Device, owner model.Membership) {
	t.Helper()
	require.NoError(t, store.ScopedByOrg(f.st.DB, f.org.ID).Model(&model.Device{}).
		Where("id = ?", device.ID).Update("owner_user_id", owner.UserID).Error)
}

// addUserGroup creates a custom group holding the given users.
func (f *evalFixture) addUserGroup(t *testing.T, name string, members ...model.Membership) model.UserGroup {
	t.Helper()
	group, err := f.svc.CreateUserGroup(context.Background(), f.org.ID, 1, name)
	require.NoError(t, err)
	ids := make([]uint, 0, len(members))
	for _, m := range members {
		ids = append(ids, m.UserID)
	}
	_, _, err = f.svc.ReplaceUserGroupMembers(context.Background(), f.org.ID, 1, group.ID, ids)
	require.NoError(t, err)
	return *group
}

func allowedIDs(t *testing.T, f *evalFixture, userID uint) (bool, []uint) {
	t.Helper()
	all, ids, err := f.svc.AllowedDeviceIDs(context.Background(), f.org.ID, userID)
	require.NoError(t, err)
	return all, ids
}

// TestEval_OwnDeviceAlwaysVisible pins D2: a member reaches the device it owns
// even when no rule mentions it, and a device owned by somebody else stays
// invisible.
func TestEval_OwnDeviceAlwaysVisible(t *testing.T) {
	f := newEvalFixture(t)
	alice := f.addMember(t, "alice@example.com", model.RoleKindMember)
	bob := f.addMember(t, "bob@example.com", model.RoleKindMember)
	mine := f.addDevice(t, "700", false)
	theirs := f.addDevice(t, "701", false)
	f.ownDevice(t, mine, alice)
	f.ownDevice(t, theirs, bob)
	f.removeDefaultRule(t)

	all, ids := allowedIDs(t, f, alice.UserID)
	require.False(t, all)
	require.Equal(t, []uint{mine.ID}, ids)

	all, ids = allowedIDs(t, f, bob.UserID)
	require.False(t, all)
	require.Equal(t, []uint{theirs.ID}, ids)
}

// TestEval_UserGroupTarget pins the new target kind: the rule reaches the
// devices owned by the members of the target group, and nobody else's.
func TestEval_UserGroupTarget(t *testing.T) {
	f := newEvalFixture(t)
	alice := f.addMember(t, "alice@example.com", model.RoleKindMember)
	bob := f.addMember(t, "bob@example.com", model.RoleKindMember)
	carol := f.addMember(t, "carol@example.com", model.RoleKindMember)
	viewers := f.addUserGroup(t, "viewers", alice)
	targets := f.addUserGroup(t, "targets", bob)
	bobDevice := f.addDevice(t, "710", false)
	carolDevice := f.addDevice(t, "711", false)
	f.ownDevice(t, bobDevice, bob)
	f.ownDevice(t, carolDevice, carol)
	f.removeDefaultRule(t)
	f.addRule(t, viewers.ID, model.AccessTargetKindUserGroup, targets.ID)

	_, ids := allowedIDs(t, f, alice.UserID)
	require.Equal(t, []uint{bobDevice.ID}, ids, "only the target group's devices")
}

// TestEval_UserGroupTargetSkipsInactiveOwner pins D7/D13: a target member whose
// membership cannot authorize anything contributes no devices through the rule.
func TestEval_UserGroupTargetSkipsInactiveOwner(t *testing.T) {
	f := newEvalFixture(t)
	alice := f.addMember(t, "alice@example.com", model.RoleKindMember)
	bob := f.addMember(t, "bob@example.com", model.RoleKindMember)
	viewers := f.addUserGroup(t, "viewers", alice)
	targets := f.addUserGroup(t, "targets", bob)
	bobDevice := f.addDevice(t, "720", false)
	f.ownDevice(t, bobDevice, bob)
	f.removeDefaultRule(t)
	f.addRule(t, viewers.ID, model.AccessTargetKindUserGroup, targets.ID)

	// Disabled membership: the device is neither reachable through the rule…
	require.NoError(t, store.ScopedByOrg(f.st.DB, f.org.ID).Model(&model.Membership{}).
		Where("user_id = ?", bob.UserID).Update("disabled", true).Error)
	_, ids := allowedIDs(t, f, alice.UserID)
	require.Empty(t, ids)
	_, ids = allowedIDs(t, f, bob.UserID)
	require.Empty(t, ids, "a disabled membership authorizes nothing at all")

	// …nor after the membership row is gone entirely, while the ownership
	// reference survives as history.
	require.NoError(t, store.ScopedByOrg(f.st.DB, f.org.ID).
		Where("user_id = ?", bob.UserID).Delete(&model.Membership{}).Error)
	_, ids = allowedIDs(t, f, alice.UserID)
	require.Empty(t, ids)
	var reloaded model.Device
	require.NoError(t, store.ScopedByOrg(f.st.DB, f.org.ID).First(&reloaded, bobDevice.ID).Error)
	require.NotNil(t, reloaded.OwnerUserID, "ownership is history and is not cleared")
}

// TestEval_EveryoneTargetCoversOwnedDevicesOnly pins D6: the implicit group as
// a target means every device somebody owns, not every device.
func TestEval_EveryoneTargetCoversOwnedDevicesOnly(t *testing.T) {
	f := newEvalFixture(t)
	alice := f.addMember(t, "alice@example.com", model.RoleKindMember)
	bob := f.addMember(t, "bob@example.com", model.RoleKindMember)
	viewers := f.addUserGroup(t, "viewers", alice)
	var everyone model.UserGroup
	require.NoError(t, store.ScopedByOrg(f.st.DB, f.org.ID).
		Where("kind = ?", model.UserGroupKindEveryone).First(&everyone).Error)
	owned := f.addDevice(t, "730", false)
	unowned := f.addDevice(t, "731", false)
	f.ownDevice(t, owned, bob)
	f.removeDefaultRule(t)
	f.addRule(t, viewers.ID, model.AccessTargetKindUserGroup, everyone.ID)

	_, ids := allowedIDs(t, f, alice.UserID)
	require.Equal(t, []uint{owned.ID}, ids)
	require.NotContains(t, ids, unowned.ID)
}

// TestEval_EveryoneTargetSkipsInactiveOwner pins the everyone target against D7
// and D13: ownership rows survive deactivation, so the membership filter — not
// the ownership column — is what keeps an offboarded member's device out of
// everybody else's peer list.
func TestEval_EveryoneTargetSkipsInactiveOwner(t *testing.T) {
	f := newEvalFixture(t)
	alice := f.addMember(t, "alice@example.com", model.RoleKindMember)
	bob := f.addMember(t, "bob@example.com", model.RoleKindMember)
	viewers := f.addUserGroup(t, "viewers", alice)
	var everyone model.UserGroup
	require.NoError(t, store.ScopedByOrg(f.st.DB, f.org.ID).
		Where("kind = ?", model.UserGroupKindEveryone).First(&everyone).Error)
	active := f.addDevice(t, "760", false)
	stopped := f.addDevice(t, "761", false)
	roleless := f.addDevice(t, "762", false)
	removed := f.addDevice(t, "763", false)
	f.ownDevice(t, active, alice)
	f.ownDevice(t, stopped, bob)
	f.ownDevice(t, roleless, bob)
	f.ownDevice(t, removed, bob)
	f.removeDefaultRule(t)
	f.addRule(t, viewers.ID, model.AccessTargetKindUserGroup, everyone.ID)

	// bob's membership loses authorization in three ways: disabled, a zero
	// role_id, and removed entirely.
	require.NoError(t, store.ScopedByOrg(f.st.DB, f.org.ID).Model(&model.Membership{}).
		Where("user_id = ? AND organization_id = ?", bob.UserID, f.org.ID).Update("disabled", true).Error)
	_, ids := allowedIDs(t, f, alice.UserID)
	require.Equal(t, []uint{active.ID}, ids, "a disabled owner's device is not covered")

	require.NoError(t, store.ScopedByOrg(f.st.DB, f.org.ID).Model(&model.Membership{}).
		Where("user_id = ? AND organization_id = ?", bob.UserID, f.org.ID).
		Updates(map[string]any{"disabled": false, "role_id": 0}).Error)
	_, ids = allowedIDs(t, f, alice.UserID)
	require.Equal(t, []uint{active.ID}, ids, "a role-less membership authorizes nothing")

	require.NoError(t, store.ScopedByOrg(f.st.DB, f.org.ID).
		Where("user_id = ?", bob.UserID).Delete(&model.Membership{}).Error)
	_, ids = allowedIDs(t, f, alice.UserID)
	require.Equal(t, []uint{active.ID}, ids, "a removed member's device is not covered either")

	var stored model.Device
	require.NoError(t, store.ScopedByOrg(f.st.DB, f.org.ID).First(&stored, removed.ID).Error)
	require.NotNil(t, stored.OwnerUserID, "the ownership reference stays as history")
}

// TestEval_DisabledDeviceHiddenFromItsOwner pins the precedence: the stop
// action outranks ownership.
func TestEval_DisabledDeviceHiddenFromItsOwner(t *testing.T) {
	f := newEvalFixture(t)
	alice := f.addMember(t, "alice@example.com", model.RoleKindMember)
	device := f.addDevice(t, "740", true)
	f.ownDevice(t, device, alice)
	f.removeDefaultRule(t)

	_, ids := allowedIDs(t, f, alice.UserID)
	require.Empty(t, ids)
	allowed, err := f.svc.CanAccess(context.Background(), f.org.ID, alice.UserID, device.ID)
	require.NoError(t, err)
	require.False(t, allowed)
}

// TestEval_CanAccessAgreesWithTheAllowedSet pins that visibility and
// reachability come from the same evaluation for every device.
func TestEval_CanAccessAgreesWithTheAllowedSet(t *testing.T) {
	f := newEvalFixture(t)
	alice := f.addMember(t, "alice@example.com", model.RoleKindMember)
	bob := f.addMember(t, "bob@example.com", model.RoleKindMember)
	viewers := f.addUserGroup(t, "viewers", alice)
	targets := f.addUserGroup(t, "targets", bob)
	mine := f.addDevice(t, "750", false)
	bobs := f.addDevice(t, "751", false)
	disabled := f.addDevice(t, "752", true)
	orphan := f.addDevice(t, "753", false)
	f.ownDevice(t, mine, alice)
	f.ownDevice(t, bobs, bob)
	f.ownDevice(t, disabled, alice)
	f.removeDefaultRule(t)
	f.addRule(t, viewers.ID, model.AccessTargetKindUserGroup, targets.ID)

	_, ids := allowedIDs(t, f, alice.UserID)
	inSet := map[uint]bool{}
	for _, id := range ids {
		inSet[id] = true
	}
	for _, device := range []model.Device{mine, bobs, disabled, orphan} {
		allowed, err := f.svc.CanAccess(context.Background(), f.org.ID, alice.UserID, device.ID)
		require.NoError(t, err)
		require.Equal(t, inSet[device.ID], allowed, "device %d", device.ID)
	}
}
