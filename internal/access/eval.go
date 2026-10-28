package access

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// AllowedDeviceIDs resolves the device visibility set of one organization
// member. all=true means the caller may reach every device of the tenant: an
// owner/admin bypass (D7) or an all_devices rule. Client-facing lists must
// still exclude disabled devices themselves (D8), because the bypass is not
// filtered here.
//
// For an ordinary member the ids are the union (D2, never first-match) of:
//
//   - the devices the member owns (D2 of the group-model wave: a member always
//     reaches its own device unless it is stopped, so ownership does not depend
//     on an administrator adding a rule);
//   - every device group targeted by a rule whose source is one of the member's
//     effective user groups: the explicit user_group_members rows plus the
//     reserved everyone group, whose membership is implicit;
//   - the devices owned by the members of a user_group target, skipping owners
//     whose membership is disabled or missing (an inactive membership
//     authorizes nothing, here as everywhere else).
//
// Devices in no group and owned by nobody are covered only by an all_devices
// rule; the 0 sentinel in target_group_id is branched on target_kind and never
// treated as a group id. Disabled devices are filtered here, and an inactive
// (missing, disabled or role-less) membership resolves to the empty set.
func (s *Service) AllowedDeviceIDs(ctx context.Context, orgID, userID uint) (bool, []uint, error) {
	return s.allowedDeviceIDs(s.db.WithContext(ctx), orgID, userID)
}

func (s *Service) allowedDeviceIDs(db *gorm.DB, orgID, userID uint) (bool, []uint, error) {
	bypass, active, err := s.bypassMembership(db, orgID, userID)
	if err != nil || !active {
		return false, nil, err
	}
	if bypass {
		return true, nil, nil
	}

	var owned []uint
	if err := store.ScopedByOrg(db, orgID).Model(&model.Device{}).
		Where("owner_user_id = ? AND disabled = ?", userID, false).
		Pluck("id", &owned).Error; err != nil {
		return false, nil, err
	}

	groupIDs, err := effectiveUserGroups(db, orgID, userID)
	if err != nil {
		return false, nil, err
	}
	if len(groupIDs) == 0 {
		return false, dedupeIDs(owned), nil
	}

	var rules []model.AccessRule
	if err := store.ScopedByOrg(db, orgID).
		Select("target_kind", "target_group_id").
		Where("source_group_id IN ?", groupIDs).
		Find(&rules).Error; err != nil {
		return false, nil, err
	}
	var deviceGroupTargets, userGroupTargets []uint
	for _, rule := range rules {
		switch rule.TargetKind {
		case model.AccessTargetKindAllDevices:
			return true, nil, nil
		case model.AccessTargetKindDeviceGroup:
			if rule.TargetGroupID != 0 {
				deviceGroupTargets = append(deviceGroupTargets, rule.TargetGroupID)
			}
		case model.AccessTargetKindUserGroup:
			if rule.TargetGroupID != 0 {
				userGroupTargets = append(userGroupTargets, rule.TargetGroupID)
			}
		}
	}

	ids := dedupeIDs(owned)
	if len(deviceGroupTargets) > 0 {
		var fromGroups []uint
		if err := store.ScopedByOrg(db, orgID).Model(&model.Device{}).
			Where("device_group_id IN ? AND disabled = ?", deviceGroupTargets, false).
			Pluck("id", &fromGroups).Error; err != nil {
			return false, nil, err
		}
		ids = append(ids, fromGroups...)
	}
	if len(userGroupTargets) > 0 {
		fromOwners, err := s.devicesOwnedByGroups(db, orgID, userGroupTargets)
		if err != nil {
			return false, nil, err
		}
		ids = append(ids, fromOwners...)
	}
	return false, dedupeIDs(ids), nil
}

// devicesOwnedByGroups expands user_group rule targets into device ids: the
// devices owned by members of those groups. The reserved everyone group means
// "every device owned by an active member" (D6) rather than every device, and an
// owner whose membership is disabled, role-less, pointing at a deleted role or
// missing contributes nothing — the same fail-closed rule the explicit-group
// branch and the caller itself obey. Ownership rows survive deactivation (D13),
// so the membership filter is what keeps an offboarded member's device out of
// everybody else's peer list.
func (s *Service) devicesOwnedByGroups(db *gorm.DB, orgID uint, groupIDs []uint) ([]uint, error) {
	reserved := make(map[uint]bool, 1)
	var everyone []uint
	if err := store.ScopedByOrg(db, orgID).Model(&model.UserGroup{}).
		Where("kind = ?", model.UserGroupKindEveryone).Pluck("id", &everyone).Error; err != nil {
		return nil, err
	}
	for _, id := range everyone {
		reserved[id] = true
	}

	// A dangling role_id (role deleted concurrently with an assignment) must be
	// treated exactly like a zero one: the membership resolves to nothing, so it
	// contributes no devices. The role set is a subquery of the same statement,
	// so the two facts are read atomically instead of through two reads a
	// concurrent deletion could straddle.
	roleIDs := authz.ResolvableRoleIDs(db, orgID)

	var activeMembers []uint
	activeLoaded := false

	var ids []uint
	explicit := make([]uint, 0, len(groupIDs))
	for _, id := range groupIDs {
		if reserved[id] {
			if !activeLoaded {
				if err := store.ScopedByOrg(db, orgID).Model(&model.Membership{}).
					Where("disabled = ? AND role_id IN (?)", false, roleIDs).
					Pluck("user_id", &activeMembers).Error; err != nil {
					return nil, err
				}
				activeMembers = dedupeIDs(activeMembers)
				activeLoaded = true
			}
			if len(activeMembers) == 0 {
				continue
			}
			var all []uint
			if err := store.ScopedByOrg(db, orgID).Model(&model.Device{}).
				Where("owner_user_id IN ? AND disabled = ?", activeMembers, false).
				Pluck("id", &all).Error; err != nil {
				return nil, err
			}
			ids = append(ids, all...)
			continue
		}
		explicit = append(explicit, id)
	}
	if len(explicit) == 0 {
		return ids, nil
	}

	var memberIDs []uint
	if err := store.ScopedByOrg(db, orgID).Model(&model.UserGroupMember{}).
		Where("group_id IN ?", explicit).Pluck("user_id", &memberIDs).Error; err != nil {
		return nil, err
	}
	memberIDs = dedupeIDs(memberIDs)
	if len(memberIDs) == 0 {
		return ids, nil
	}

	var activeOwners []uint
	if err := store.ScopedByOrg(db, orgID).Model(&model.Membership{}).
		Where("user_id IN ? AND disabled = ? AND role_id IN (?)", memberIDs, false, roleIDs).
		Pluck("user_id", &activeOwners).Error; err != nil {
		return nil, err
	}
	activeOwners = dedupeIDs(activeOwners)
	if len(activeOwners) == 0 {
		return ids, nil
	}

	var fromOwners []uint
	if err := store.ScopedByOrg(db, orgID).Model(&model.Device{}).
		Where("owner_user_id IN ? AND disabled = ?", activeOwners, false).
		Pluck("id", &fromOwners).Error; err != nil {
		return nil, err
	}
	return dedupeIDs(append(ids, fromOwners...)), nil
}

// CanAccess reports whether the user may reach this one device. It is the
// single-device form of the same evaluation the peer list uses, so visibility
// and reachability cannot disagree. A device outside the tenant, a disabled
// device and an inactive membership all resolve to false; the caller maps that
// onto 404 so the device's existence does not leak.
func (s *Service) CanAccess(ctx context.Context, orgID, userID, deviceID uint) (bool, error) {
	return s.canAccess(s.db.WithContext(ctx), orgID, userID, deviceID)
}

// CanAccessTx runs the same evaluation on a transaction the caller owns, for
// decisions that must be taken while holding a lock. Ticket redemption uses it
// because every access mutation takes the organization row lock: a revocation
// that committed before that lock was granted is visible here, instead of
// landing after a decision already taken outside the transaction.
func (s *Service) CanAccessTx(tx *gorm.DB, orgID, userID, deviceID uint) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("access: a transaction is required")
	}
	return s.canAccess(tx, orgID, userID, deviceID)
}

func (s *Service) canAccess(db *gorm.DB, orgID, userID, deviceID uint) (bool, error) {
	if orgID == 0 || userID == 0 || deviceID == 0 {
		return false, nil
	}

	var device model.Device
	err := store.ScopedByOrg(db, orgID).Select("id", "disabled").First(&device, deviceID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if device.Disabled {
		// D8: a stopped device is unreachable ahead of any rule, including the
		// administrator bypass.
		return false, nil
	}

	all, ids, err := s.allowedDeviceIDs(db, orgID, userID)
	if err != nil {
		return false, err
	}
	if all {
		return true, nil
	}
	for _, id := range ids {
		if id == deviceID {
			return true, nil
		}
	}
	return false, nil
}

// DeviceDisabled reports whether the device exists in the tenant and is
// disabled. The ticket redemption path uses it to keep the documented conflict
// response for a ticket issued before an administrator stopped the device,
// instead of collapsing that state into the opaque access-control 404.
func (s *Service) DeviceDisabled(ctx context.Context, orgID, deviceID uint) (bool, error) {
	if orgID == 0 || deviceID == 0 {
		return false, nil
	}
	var device model.Device
	err := store.ScopedByOrg(s.db.WithContext(ctx), orgID).
		Select("id", "disabled").First(&device, deviceID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return device.Disabled, nil
}

// bypassMembership resolves the membership and its role kind. bypass reports
// whether the member is an owner or admin (D7); active reports whether the
// membership may evaluate rules at all. A missing row, a disabled membership,
// a zero role_id and a missing role all resolve to active=false without an
// error, matching authz.Resolve's fail-closed contract: authorization is never
// guessed from the legacy role string or from the first role row of the
// organization.
func (s *Service) bypassMembership(db *gorm.DB, orgID, userID uint) (bypass, active bool, err error) {
	if orgID == 0 || userID == 0 {
		return false, false, nil
	}
	var membership model.Membership
	err = store.ScopedByOrg(db, orgID).
		Select("id", "role_id", "disabled").
		Where("user_id = ?", userID).
		First(&membership).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	if membership.Disabled || membership.RoleID == 0 {
		return false, false, nil
	}
	var role model.Role
	err = store.ScopedByOrg(db, orgID).Select("id", "kind").First(&role, membership.RoleID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	return role.Kind == model.RoleKindOwner || role.Kind == model.RoleKindAdmin, true, nil
}

// effectiveUserGroups returns the source groups of a member: the groups with an
// explicit membership row plus the reserved everyone group. Everyone membership
// is implicit and stores no member rows, so omitting it would hide every device
// from members of an organization that still has the seeded default rule.
func effectiveUserGroups(db *gorm.DB, orgID, userID uint) ([]uint, error) {
	var explicit []uint
	if err := store.ScopedByOrg(db, orgID).Model(&model.UserGroupMember{}).
		Where("user_id = ?", userID).Pluck("group_id", &explicit).Error; err != nil {
		return nil, err
	}
	groups := dedupeIDs(explicit)

	var everyone model.UserGroup
	if err := store.ScopedByOrg(db, orgID).
		Select("id").Where("kind = ?", model.UserGroupKindEveryone).
		Order("id").Limit(1).Find(&everyone).Error; err != nil {
		return nil, err
	}
	if everyone.ID != 0 {
		groups = append(groups, everyone.ID)
	}
	return groups, nil
}
