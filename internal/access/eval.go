package access

import (
	"context"
	"errors"

	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// AllowedDeviceIDs resolves the device visibility set of one organization
// member. all=true means the caller may reach every device of the tenant: an
// owner/admin bypass (D7) or an all_devices rule. Client-facing lists must
// still exclude disabled devices themselves (D8), because the bypass is not
// filtered here.
//
// For an ordinary member the ids are the union (D2, never first-match) of every
// device group targeted by a rule whose source is one of the member's effective
// user groups: the explicit user_group_members rows plus the reserved everyone
// group, whose membership is implicit. Devices in no group are covered only by
// an all_devices rule; the 0 sentinel in target_group_id is branched on
// target_kind and never treated as a group id. Disabled devices are filtered
// here, and an inactive (missing, disabled or role-less) membership resolves to
// the empty set.
func (s *Service) AllowedDeviceIDs(ctx context.Context, orgID, userID uint) (bool, []uint, error) {
	db := s.db.WithContext(ctx)
	bypass, active, err := s.bypassMembership(db, orgID, userID)
	if err != nil || !active {
		return false, nil, err
	}
	if bypass {
		return true, nil, nil
	}

	groupIDs, err := effectiveUserGroups(db, orgID, userID)
	if err != nil {
		return false, nil, err
	}
	if len(groupIDs) == 0 {
		return false, []uint{}, nil
	}

	var rules []model.AccessRule
	if err := store.ScopedByOrg(db, orgID).
		Select("target_kind", "target_group_id").
		Where("source_group_id IN ?", groupIDs).
		Find(&rules).Error; err != nil {
		return false, nil, err
	}
	targets := make([]uint, 0, len(rules))
	for _, rule := range rules {
		switch rule.TargetKind {
		case model.AccessTargetKindAllDevices:
			return true, nil, nil
		case model.AccessTargetKindDeviceGroup:
			if rule.TargetGroupID != 0 {
				targets = append(targets, rule.TargetGroupID)
			}
		}
	}
	if len(targets) == 0 {
		return false, []uint{}, nil
	}

	var ids []uint
	if err := store.ScopedByOrg(db, orgID).Model(&model.Device{}).
		Where("device_group_id IN ? AND disabled = ?", targets, false).
		Pluck("id", &ids).Error; err != nil {
		return false, nil, err
	}
	return false, ids, nil
}

// CanAccess reports whether the user may reach this one device. It is the
// single-device form of the same evaluation the peer list uses, so visibility
// and reachability cannot disagree. A device outside the tenant, a disabled
// device and an inactive membership all resolve to false; the caller maps that
// onto 404 so the device's existence does not leak.
func (s *Service) CanAccess(ctx context.Context, orgID, userID, deviceID uint) (bool, error) {
	if orgID == 0 || userID == 0 || deviceID == 0 {
		return false, nil
	}
	db := s.db.WithContext(ctx)

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

	all, ids, err := s.AllowedDeviceIDs(ctx, orgID, userID)
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

	var everyone uint
	if err := store.ScopedByOrg(db, orgID).Model(&model.UserGroup{}).
		Where("kind = ?", model.UserGroupKindEveryone).Pluck("id", &everyone).Error; err != nil {
		return nil, err
	}
	if everyone != 0 {
		groups = append(groups, everyone)
	}
	return groups, nil
}
