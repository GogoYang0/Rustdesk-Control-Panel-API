// Package access owns the access-control domain: user groups, device groups
// and the allow-only rules that decide which devices a member can see and
// reach. The same evaluation gates the compat peer list and ticket issue and
// redemption, so visibility and reachability never disagree.
package access

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// Migrate converges the access-control defaults for every organization: the
// reserved everyone group and its all-devices rule. It runs on every startup
// and is idempotent per organization rather than guarded by a one-shot marker
// — an organization that appears after a previous run (a harness fixture, a
// restored database) must still get its defaults, or its ordinary members
// would see an empty device list forever. A failure aborts startup so the next
// boot retries from the same state.
func Migrate(db *gorm.DB) error {
	return db.Transaction(func(tx *gorm.DB) error {
		var orgIDs []uint
		if err := tx.Model(&model.Organization{}).Order("id").Pluck("id", &orgIDs).Error; err != nil {
			return fmt.Errorf("list organizations: %w", err)
		}
		for _, orgID := range orgIDs {
			if err := EnsureDefaultsTx(tx, orgID); err != nil {
				return fmt.Errorf("seed access defaults for organization %d: %w", orgID, err)
			}
		}
		return nil
	})
}

// EnsureDefaultsTx makes sure the organization has its everyone group and the
// everyone -> all_devices rule. It is idempotent and runs inside the caller's
// transaction, so organization creation commits its defaults atomically.
func EnsureDefaultsTx(tx *gorm.DB, orgID uint) error {
	group, err := everyoneGroupTx(tx, orgID)
	if err != nil {
		return err
	}
	if err := store.ScopedByOrg(tx, orgID).Clauses(clause.OnConflict{DoNothing: true}).
		Create(&model.AccessRule{
			OrganizationID: orgID,
			SourceGroupID:  group.ID,
			TargetKind:     model.AccessTargetKindAllDevices,
			TargetGroupID:  0,
		}).Error; err != nil {
		return fmt.Errorf("seed default access rule: %w", err)
	}
	return nil
}

// everyoneGroupTx returns the reserved everyone group, creating it when the
// organization predates the access-control migration.
func everyoneGroupTx(tx *gorm.DB, orgID uint) (*model.UserGroup, error) {
	var group model.UserGroup
	err := store.ScopedByOrg(tx, orgID).
		Where("kind = ?", model.UserGroupKindEveryone).First(&group).Error
	if err == nil {
		return &group, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("load everyone group: %w", err)
	}
	group = model.UserGroup{
		OrganizationID: orgID,
		Name:           model.EveryoneGroupName,
		Kind:           model.UserGroupKindEveryone,
	}
	// Two concurrent writers converge on one row: the unique
	// (organization_id, name) index decides and the loser re-reads.
	if err := store.ScopedByOrg(tx, orgID).Clauses(clause.OnConflict{DoNothing: true}).
		Create(&group).Error; err != nil {
		return nil, fmt.Errorf("create everyone group: %w", err)
	}
	if err := store.ScopedByOrg(tx, orgID).
		Where("kind = ?", model.UserGroupKindEveryone).First(&group).Error; err != nil {
		return nil, fmt.Errorf("reload everyone group: %w", err)
	}
	return &group, nil
}

// Service-level errors mapped to HTTP statuses by the handler.
var (
	ErrGroupNotFound    = errors.New("user group not found")
	ErrReservedGroup    = errors.New("reserved user group")
	ErrGroupNameTaken   = errors.New("user group name already in use")
	ErrInvalidGroupName = errors.New("invalid user group name")
	ErrInvalidMember    = errors.New("invalid user group member")
	// ErrAuditUnavailable refuses a group mutation when the configured auditor
	// cannot record inside the same transaction: no audit, no change.
	ErrAuditUnavailable = errors.New("transactional auditor unavailable")

	ErrDeviceGroupNotFound    = errors.New("device group not found")
	ErrDeviceGroupNameTaken   = errors.New("device group name already in use")
	ErrInvalidDeviceGroupName = errors.New("invalid device group name")
	ErrInvalidDevice          = errors.New("invalid device")
)

// maxGroupNameLen matches the size:64 column of model.UserGroup.
const maxGroupNameLen = 64

// GroupView is one user group together with its explicit member ids. The
// everyone group has no member rows (membership is implicit), so its list is
// always empty.
type GroupView struct {
	Group     model.UserGroup
	MemberIDs []uint
}

// DeviceGroupView is one device group together with the ids of its devices. A
// device belongs to at most one group, so the ids never appear in two views.
type DeviceGroupView struct {
	Group     model.DeviceGroup
	DeviceIDs []uint
}

// Service owns the access-control writes: groups, memberships (device groups
// and rules arrive in later tasks). Every write records its audit entry on the
// same transaction, and a service built without a transactional recorder
// refuses to write at all.
type Service struct {
	db       *gorm.DB
	recorder audit.TxRecorder
	now      func() time.Time
}

// NewService builds the service. The database handle is unscoped; every
// statement goes through store.ScopedByOrg.
func NewService(db *gorm.DB, recorder audit.TxRecorder, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{db: db, recorder: recorder, now: now}
}

// ListUserGroups returns the organization's groups ordered by id, including the
// reserved everyone group, with their explicit member ids for PUT round-tripping.
func (s *Service) ListUserGroups(ctx context.Context, orgID uint) ([]GroupView, error) {
	db := s.db.WithContext(ctx)
	var groups []model.UserGroup
	if err := store.ScopedByOrg(db, orgID).Order("id").Find(&groups).Error; err != nil {
		return nil, err
	}
	views := make([]GroupView, 0, len(groups))
	if len(groups) == 0 {
		return views, nil
	}
	ids := make([]uint, 0, len(groups))
	for _, g := range groups {
		ids = append(ids, g.ID)
	}
	var members []model.UserGroupMember
	if err := store.ScopedByOrg(db, orgID).
		Where("group_id IN ?", ids).Find(&members).Error; err != nil {
		return nil, err
	}
	byGroup := make(map[uint][]uint, len(groups))
	for _, m := range members {
		byGroup[m.GroupID] = append(byGroup[m.GroupID], m.UserID)
	}
	for _, g := range groups {
		memberIDs := byGroup[g.ID]
		if memberIDs == nil {
			memberIDs = []uint{}
		}
		views = append(views, GroupView{Group: g, MemberIDs: memberIDs})
	}
	return views, nil
}

// UserGroupView reloads one group with its explicit member ids. Create and
// rename responses use it so their member_ids stay consistent with the list
// (a client round-trips that shape into the PUT replacement).
func (s *Service) UserGroupView(ctx context.Context, orgID, groupID uint) (GroupView, error) {
	group, err := groupByID(s.db.WithContext(ctx), orgID, groupID)
	if err != nil {
		return GroupView{}, err
	}
	var members []model.UserGroupMember
	if err := store.ScopedByOrg(s.db.WithContext(ctx), orgID).
		Where("group_id = ?", groupID).Find(&members).Error; err != nil {
		return GroupView{}, err
	}
	ids := make([]uint, 0, len(members))
	for _, m := range members {
		ids = append(ids, m.UserID)
	}
	return GroupView{Group: *group, MemberIDs: ids}, nil
}

// CreateUserGroup adds a custom group. The reserved name is refused in any
// casing, and duplicate names are rejected before the insert.
func (s *Service) CreateUserGroup(ctx context.Context, orgID, actorID uint, name string) (*model.UserGroup, error) {
	clean, err := cleanGroupName(name)
	if err != nil {
		return nil, err
	}
	var group model.UserGroup
	err = s.write(ctx, func(tx *gorm.DB) error {
		if err := lockOrgRow(tx, orgID); err != nil {
			return err
		}
		if err := ensureGroupNameFree(tx, orgID, clean, 0); err != nil {
			return err
		}
		group = model.UserGroup{
			OrganizationID: orgID,
			Name:           clean,
			Kind:           model.UserGroupKindCustom,
		}
		if err := store.ScopedByOrg(tx, orgID).Create(&group).Error; err != nil {
			return mapGroupNameConflict(err)
		}
		return s.record(tx, audit.Entry{
			OrganizationID: orgID,
			ActorUserID:    actorID,
			Action:         "access.user_group.create",
			TargetType:     "user_group",
			TargetID:       fmt.Sprint(group.ID),
			Detail:         map[string]any{"name": group.Name},
		})
	})
	if err != nil {
		return nil, err
	}
	return &group, nil
}

// RenameUserGroup renames a custom group. The everyone group can never be
// renamed, and the new name follows the same reserved/unique rules as creation.
func (s *Service) RenameUserGroup(ctx context.Context, orgID, actorID, groupID uint, name string) (*model.UserGroup, error) {
	clean, err := cleanGroupName(name)
	if err != nil {
		return nil, err
	}
	var updated model.UserGroup
	err = s.write(ctx, func(tx *gorm.DB) error {
		if err := lockOrgRow(tx, orgID); err != nil {
			return err
		}
		group, err := groupByID(tx, orgID, groupID)
		if err != nil {
			return err
		}
		if group.Kind == model.UserGroupKindEveryone {
			return ErrReservedGroup
		}
		if group.Name == clean {
			updated = *group
			return nil
		}
		if err := ensureGroupNameFree(tx, orgID, clean, group.ID); err != nil {
			return err
		}
		res := store.ScopedByOrg(tx, orgID).Model(&model.UserGroup{}).
			Where("id = ? AND kind = ?", group.ID, model.UserGroupKindCustom).
			Updates(map[string]any{"name": clean, "updated_at": s.now().UTC()})
		if res.Error != nil {
			return mapGroupNameConflict(res.Error)
		}
		if res.RowsAffected == 0 {
			// The row stopped being a custom group between the read and the
			// update; audited success would claim a rename that never happened.
			return ErrGroupNotFound
		}
		reloaded, err := groupByID(tx, orgID, group.ID)
		if err != nil {
			return err
		}
		updated = *reloaded
		return s.record(tx, audit.Entry{
			OrganizationID: orgID,
			ActorUserID:    actorID,
			Action:         "access.user_group.update",
			TargetType:     "user_group",
			TargetID:       fmt.Sprint(group.ID),
			Detail:         map[string]any{"name": clean, "previous_name": group.Name},
		})
	})
	if err != nil {
		return nil, err
	}
	return &updated, nil
}

// DeleteUserGroup removes a custom group together with its member rows and the
// rules whose source is that group. It returns how many rules were cascaded so
// the handler can report them.
func (s *Service) DeleteUserGroup(ctx context.Context, orgID, actorID, groupID uint) (int, error) {
	cascaded := 0
	err := s.write(ctx, func(tx *gorm.DB) error {
		if err := lockOrgRow(tx, orgID); err != nil {
			return err
		}
		group, err := groupByID(tx, orgID, groupID)
		if err != nil {
			return err
		}
		if group.Kind == model.UserGroupKindEveryone {
			return ErrReservedGroup
		}
		var rules []model.AccessRule
		if err := store.ScopedByOrg(tx, orgID).
			Where("source_group_id = ?", group.ID).Find(&rules).Error; err != nil {
			return err
		}
		if len(rules) > 0 {
			if err := store.ScopedByOrg(tx, orgID).
				Where("source_group_id = ?", group.ID).
				Delete(&model.AccessRule{}).Error; err != nil {
				return err
			}
			for _, rule := range rules {
				if err := s.record(tx, audit.Entry{
					OrganizationID: orgID,
					ActorUserID:    actorID,
					Action:         "access.rule.delete",
					TargetType:     "access_rule",
					TargetID:       fmt.Sprint(rule.ID),
					Detail: map[string]any{
						"source_group_id": rule.SourceGroupID,
						"target_kind":     rule.TargetKind,
						"target_group_id": rule.TargetGroupID,
						"cascade":         true,
					},
				}); err != nil {
					return err
				}
			}
		}
		if err := store.ScopedByOrg(tx, orgID).
			Where("group_id = ?", group.ID).
			Delete(&model.UserGroupMember{}).Error; err != nil {
			return err
		}
		res := store.ScopedByOrg(tx, orgID).
			Where("id = ? AND kind = ?", group.ID, model.UserGroupKindCustom).
			Delete(&model.UserGroup{})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrGroupNotFound
		}
		cascaded = len(rules)
		return s.record(tx, audit.Entry{
			OrganizationID: orgID,
			ActorUserID:    actorID,
			Action:         "access.user_group.delete",
			TargetType:     "user_group",
			TargetID:       fmt.Sprint(group.ID),
			Detail:         map[string]any{"name": group.Name, "deleted_rules": cascaded},
		})
	})
	if err != nil {
		return 0, err
	}
	return cascaded, nil
}

// ReplaceUserGroupMembers replaces the explicit member set of a custom group.
// Every requested user must hold a membership in the organization; one invalid
// id rejects the whole request, and an identical set changes nothing.
func (s *Service) ReplaceUserGroupMembers(ctx context.Context, orgID, actorID, groupID uint, userIDs []uint) (removed, added int, err error) {
	wanted := dedupeIDs(userIDs)
	err = s.write(ctx, func(tx *gorm.DB) error {
		if err := lockOrgRow(tx, orgID); err != nil {
			return err
		}
		group, err := groupByID(tx, orgID, groupID)
		if err != nil {
			return err
		}
		if group.Kind == model.UserGroupKindEveryone {
			return ErrReservedGroup
		}
		if err := validateMembers(tx, orgID, wanted); err != nil {
			return err
		}
		var current []model.UserGroupMember
		if err := store.ScopedByOrg(tx, orgID).
			Where("group_id = ?", group.ID).Find(&current).Error; err != nil {
			return err
		}
		have := make(map[uint]bool, len(current))
		for _, m := range current {
			have[m.UserID] = true
		}
		keep := make(map[uint]bool, len(wanted))
		for _, id := range wanted {
			keep[id] = true
		}
		var toDelete, toAdd []uint
		for _, m := range current {
			if !keep[m.UserID] {
				toDelete = append(toDelete, m.UserID)
			}
		}
		for _, id := range wanted {
			if !have[id] {
				toAdd = append(toAdd, id)
			}
		}
		if len(toDelete) > 0 {
			if err := store.ScopedByOrg(tx, orgID).
				Where("group_id = ? AND user_id IN ?", group.ID, toDelete).
				Delete(&model.UserGroupMember{}).Error; err != nil {
				return err
			}
		}
		for _, id := range toAdd {
			if err := store.ScopedByOrg(tx, orgID).Create(&model.UserGroupMember{
				OrganizationID: orgID,
				GroupID:        group.ID,
				UserID:         id,
			}).Error; err != nil {
				return err
			}
		}
		removed, added = len(toDelete), len(toAdd)
		if removed == 0 && added == 0 {
			return nil
		}
		return s.record(tx, audit.Entry{
			OrganizationID: orgID,
			ActorUserID:    actorID,
			Action:         "access.user_group.members",
			TargetType:     "user_group",
			TargetID:       fmt.Sprint(group.ID),
			Detail:         map[string]any{"user_ids": wanted, "added": added, "removed": removed},
		})
	})
	if err != nil {
		return 0, 0, err
	}
	return removed, added, nil
}

// ListDeviceGroups returns the organization's device groups ordered by id,
// each with the ids of the devices currently assigned to it.
func (s *Service) ListDeviceGroups(ctx context.Context, orgID uint) ([]DeviceGroupView, error) {
	db := s.db.WithContext(ctx)
	var groups []model.DeviceGroup
	if err := store.ScopedByOrg(db, orgID).Order("id").Find(&groups).Error; err != nil {
		return nil, err
	}
	views := make([]DeviceGroupView, 0, len(groups))
	if len(groups) == 0 {
		return views, nil
	}
	ids := make([]uint, 0, len(groups))
	for _, group := range groups {
		ids = append(ids, group.ID)
	}
	var devices []model.Device
	if err := store.ScopedByOrg(db, orgID).
		Where("device_group_id IN ?", ids).Find(&devices).Error; err != nil {
		return nil, err
	}
	byGroup := make(map[uint][]uint, len(groups))
	for _, device := range devices {
		if device.DeviceGroupID == nil {
			continue
		}
		byGroup[*device.DeviceGroupID] = append(byGroup[*device.DeviceGroupID], device.ID)
	}
	for _, group := range groups {
		deviceIDs := byGroup[group.ID]
		if deviceIDs == nil {
			deviceIDs = []uint{}
		}
		views = append(views, DeviceGroupView{Group: group, DeviceIDs: deviceIDs})
	}
	return views, nil
}

// DeviceGroupViewByID reloads one device group with its device ids for the
// create/rename responses.
func (s *Service) DeviceGroupViewByID(ctx context.Context, orgID, groupID uint) (DeviceGroupView, error) {
	db := s.db.WithContext(ctx)
	group, err := deviceGroupByID(db, orgID, groupID)
	if err != nil {
		return DeviceGroupView{}, err
	}
	var devices []model.Device
	if err := store.ScopedByOrg(db, orgID).
		Where("device_group_id = ?", groupID).Find(&devices).Error; err != nil {
		return DeviceGroupView{}, err
	}
	ids := make([]uint, 0, len(devices))
	for _, device := range devices {
		ids = append(ids, device.ID)
	}
	return DeviceGroupView{Group: *group, DeviceIDs: ids}, nil
}

// CreateDeviceGroup adds a device group. Names are unique per organization
// (case-insensitive) and are not reserved.
func (s *Service) CreateDeviceGroup(ctx context.Context, orgID, actorID uint, name string) (*model.DeviceGroup, error) {
	clean, err := cleanDeviceGroupName(name)
	if err != nil {
		return nil, err
	}
	var group model.DeviceGroup
	err = s.write(ctx, func(tx *gorm.DB) error {
		if err := lockOrgRow(tx, orgID); err != nil {
			return err
		}
		if err := ensureDeviceGroupNameFree(tx, orgID, clean, 0); err != nil {
			return err
		}
		group = model.DeviceGroup{OrganizationID: orgID, Name: clean}
		if err := store.ScopedByOrg(tx, orgID).Create(&group).Error; err != nil {
			return mapDeviceGroupNameConflict(err)
		}
		return s.record(tx, audit.Entry{
			OrganizationID: orgID,
			ActorUserID:    actorID,
			Action:         "access.device_group.create",
			TargetType:     "device_group",
			TargetID:       fmt.Sprint(group.ID),
			Detail:         map[string]any{"name": group.Name},
		})
	})
	if err != nil {
		return nil, err
	}
	return &group, nil
}

// RenameDeviceGroup renames a device group.
func (s *Service) RenameDeviceGroup(ctx context.Context, orgID, actorID, groupID uint, name string) (*model.DeviceGroup, error) {
	clean, err := cleanDeviceGroupName(name)
	if err != nil {
		return nil, err
	}
	var updated model.DeviceGroup
	err = s.write(ctx, func(tx *gorm.DB) error {
		if err := lockOrgRow(tx, orgID); err != nil {
			return err
		}
		group, err := deviceGroupByID(tx, orgID, groupID)
		if err != nil {
			return err
		}
		if group.Name == clean {
			updated = *group
			return nil
		}
		if err := ensureDeviceGroupNameFree(tx, orgID, clean, group.ID); err != nil {
			return err
		}
		res := store.ScopedByOrg(tx, orgID).Model(&model.DeviceGroup{}).
			Where("id = ?", group.ID).
			Updates(map[string]any{"name": clean, "updated_at": s.now().UTC()})
		if res.Error != nil {
			return mapDeviceGroupNameConflict(res.Error)
		}
		if res.RowsAffected == 0 {
			return ErrDeviceGroupNotFound
		}
		reloaded, err := deviceGroupByID(tx, orgID, group.ID)
		if err != nil {
			return err
		}
		updated = *reloaded
		return s.record(tx, audit.Entry{
			OrganizationID: orgID,
			ActorUserID:    actorID,
			Action:         "access.device_group.update",
			TargetType:     "device_group",
			TargetID:       fmt.Sprint(group.ID),
			Detail:         map[string]any{"name": clean, "previous_name": group.Name},
		})
	})
	if err != nil {
		return nil, err
	}
	return &updated, nil
}

// DeleteDeviceGroup deletes a device group. Devices assigned to it return to
// ungrouped and every rule targeting it is cascaded with its own audit entry.
// It returns how many rules were removed and how many devices were ungrouped.
func (s *Service) DeleteDeviceGroup(ctx context.Context, orgID, actorID, groupID uint) (removedRules, ungrouped int, err error) {
	err = s.write(ctx, func(tx *gorm.DB) error {
		if err := lockOrgRow(tx, orgID); err != nil {
			return err
		}
		group, err := deviceGroupByID(tx, orgID, groupID)
		if err != nil {
			return err
		}
		var rules []model.AccessRule
		if err := store.ScopedByOrg(tx, orgID).
			Where("target_kind = ? AND target_group_id = ?",
				model.AccessTargetKindDeviceGroup, group.ID).
			Find(&rules).Error; err != nil {
			return err
		}
		if len(rules) > 0 {
			if err := store.ScopedByOrg(tx, orgID).
				Where("target_kind = ? AND target_group_id = ?",
					model.AccessTargetKindDeviceGroup, group.ID).
				Delete(&model.AccessRule{}).Error; err != nil {
				return err
			}
			for _, rule := range rules {
				if err := s.record(tx, audit.Entry{
					OrganizationID: orgID,
					ActorUserID:    actorID,
					Action:         "access.rule.delete",
					TargetType:     "access_rule",
					TargetID:       fmt.Sprint(rule.ID),
					Detail: map[string]any{
						"source_group_id": rule.SourceGroupID,
						"target_kind":     rule.TargetKind,
						"target_group_id": rule.TargetGroupID,
						"cascade":         true,
					},
				}); err != nil {
					return err
				}
			}
		}
		res := store.ScopedByOrg(tx, orgID).Model(&model.Device{}).
			Where("device_group_id = ?", group.ID).
			Update("device_group_id", nil)
		if res.Error != nil {
			return res.Error
		}
		ungrouped = int(res.RowsAffected)

		del := store.ScopedByOrg(tx, orgID).Delete(&model.DeviceGroup{}, group.ID)
		if del.Error != nil {
			return del.Error
		}
		if del.RowsAffected == 0 {
			return ErrDeviceGroupNotFound
		}
		removedRules = len(rules)
		return s.record(tx, audit.Entry{
			OrganizationID: orgID,
			ActorUserID:    actorID,
			Action:         "access.device_group.delete",
			TargetType:     "device_group",
			TargetID:       fmt.Sprint(group.ID),
			Detail: map[string]any{
				"name":              group.Name,
				"removed_rules":     removedRules,
				"ungrouped_devices": ungrouped,
			},
		})
	})
	if err != nil {
		return 0, 0, err
	}
	return removedRules, ungrouped, nil
}

// ReplaceDeviceGroupDevices replaces the device set of a group. Target devices
// are moved in from whatever group they were in (one device, one group); group
// members not listed are released back to ungrouped. Every requested device
// must belong to the organization, otherwise the whole request is rejected.
func (s *Service) ReplaceDeviceGroupDevices(ctx context.Context, orgID, actorID, groupID uint, deviceIDs []uint) (added, removed int, err error) {
	wanted := dedupeIDs(deviceIDs)
	err = s.write(ctx, func(tx *gorm.DB) error {
		if err := lockOrgRow(tx, orgID); err != nil {
			return err
		}
		group, err := deviceGroupByID(tx, orgID, groupID)
		if err != nil {
			return err
		}
		if err := validateDevices(tx, orgID, wanted); err != nil {
			return err
		}
		var current []model.Device
		if err := store.ScopedByOrg(tx, orgID).
			Where("device_group_id = ?", group.ID).Find(&current).Error; err != nil {
			return err
		}
		have := make(map[uint]bool, len(current))
		for _, device := range current {
			have[device.ID] = true
		}
		keep := make(map[uint]bool, len(wanted))
		for _, id := range wanted {
			keep[id] = true
		}
		var toRelease, toAdd []uint
		for _, device := range current {
			if !keep[device.ID] {
				toRelease = append(toRelease, device.ID)
			}
		}
		for _, id := range wanted {
			if !have[id] {
				toAdd = append(toAdd, id)
			}
		}
		if len(toRelease) > 0 {
			if err := store.ScopedByOrg(tx, orgID).Model(&model.Device{}).
				Where("device_group_id = ? AND id IN ?", group.ID, toRelease).
				Update("device_group_id", nil).Error; err != nil {
				return err
			}
		}
		if len(toAdd) > 0 {
			// This single UPDATE also detaches the devices from any previous
			// group, which is what enforces "one device belongs to one group".
			if err := store.ScopedByOrg(tx, orgID).Model(&model.Device{}).
				Where("id IN ?", toAdd).
				Update("device_group_id", group.ID).Error; err != nil {
				return err
			}
		}
		added, removed = len(toAdd), len(toRelease)
		if added == 0 && removed == 0 {
			return nil
		}
		return s.record(tx, audit.Entry{
			OrganizationID: orgID,
			ActorUserID:    actorID,
			Action:         "access.device_group.devices",
			TargetType:     "device_group",
			TargetID:       fmt.Sprint(group.ID),
			Detail:         map[string]any{"device_ids": wanted, "added": added, "removed": removed},
		})
	})
	if err != nil {
		return 0, 0, err
	}
	return added, removed, nil
}

// write runs fn inside one transaction, refusing to start without a
// transactional recorder so an unaudited group change can never commit.
func (s *Service) write(ctx context.Context, fn func(tx *gorm.DB) error) error {
	if s.recorder == nil {
		return ErrAuditUnavailable
	}
	return s.db.WithContext(ctx).Transaction(fn)
}

// record writes one audit entry on the caller's transaction.
func (s *Service) record(tx *gorm.DB, entry audit.Entry) error {
	if s.recorder == nil {
		return ErrAuditUnavailable
	}
	return s.recorder.RecordTx(tx, entry)
}

// groupByID loads one group of the tenant or reports ErrGroupNotFound.
func groupByID(tx *gorm.DB, orgID, groupID uint) (*model.UserGroup, error) {
	var group model.UserGroup
	if err := store.ScopedByOrg(tx, orgID).First(&group, groupID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrGroupNotFound
		}
		return nil, err
	}
	return &group, nil
}

// cleanGroupName trims and bounds a display name and refuses the reserved
// everyone name in any casing.
func cleanGroupName(name string) (string, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" || len([]rune(trimmed)) > maxGroupNameLen {
		return "", ErrInvalidGroupName
	}
	if strings.EqualFold(trimmed, model.EveryoneGroupName) {
		return "", ErrReservedGroup
	}
	return trimmed, nil
}

// ensureGroupNameFree rejects a name already used by another group of the
// organization. The comparison happens in Go with strings.EqualFold so
// non-ASCII names behave identically on SQLite, PostgreSQL and MySQL instead of
// following each database's LOWER() collation.
func ensureGroupNameFree(tx *gorm.DB, orgID uint, name string, exceptID uint) error {
	var existing []model.UserGroup
	if err := store.ScopedByOrg(tx, orgID).
		Select("id", "name").Find(&existing).Error; err != nil {
		return err
	}
	for _, group := range existing {
		if exceptID != 0 && group.ID == exceptID {
			continue
		}
		if strings.EqualFold(group.Name, name) {
			return ErrGroupNameTaken
		}
	}
	return nil
}

// validateMembers rejects the whole request when any requested user has no
// membership in the organization (a foreign or nonexistent id).
func validateMembers(tx *gorm.DB, orgID uint, ids []uint) error {
	if len(ids) == 0 {
		return nil
	}
	query := store.ScopedByOrg(tx, orgID).Model(&model.Membership{})
	if tx.Name() != "sqlite" {
		// Lock the validated memberships so a concurrent member removal either
		// waits for this replacement (and deletes the fresh group rows) or
		// commits first, in which case this request sees the user gone and
		// rejects the whole set. Without the lock the rows validated here could
		// be deleted underneath us and resurrected as stale group grants on
		// re-invitation.
		query = query.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var found []uint
	if err := query.
		Where("user_id IN ?", ids).Pluck("user_id", &found).Error; err != nil {
		return err
	}
	if len(found) != len(ids) {
		return ErrInvalidMember
	}
	return nil
}

// dedupeIDs removes repeated user ids while preserving their order.
func dedupeIDs(ids []uint) []uint {
	seen := make(map[uint]bool, len(ids))
	out := make([]uint, 0, len(ids))
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// mapGroupNameConflict translates a unique-index violation into the domain
// error the handler maps onto 409. The string fallback covers drivers without
// an ErrorTranslator (the SQLite driver used in local runs and tests), so a
// race past the pre-check does not surface as a 500.
func mapGroupNameConflict(err error) error {
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return ErrGroupNameTaken
	}
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "unique") || strings.Contains(lower, "duplicate") {
		return ErrGroupNameTaken
	}
	return err
}

// lockOrgRow takes a write lock on the organization row so the name check and
// the insert serialise across concurrent requests. SQLite serialises writers
// itself and has no SELECT ... FOR UPDATE, so the clause is skipped there.
func lockOrgRow(tx *gorm.DB, orgID uint) error {
	query := tx
	if tx.Name() != "sqlite" {
		query = query.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var org model.Organization
	return query.First(&org, orgID).Error
}

// deviceGroupByID loads one device group of the tenant or reports
// ErrDeviceGroupNotFound.
func deviceGroupByID(db *gorm.DB, orgID, groupID uint) (*model.DeviceGroup, error) {
	var group model.DeviceGroup
	if err := store.ScopedByOrg(db, orgID).First(&group, groupID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrDeviceGroupNotFound
		}
		return nil, err
	}
	return &group, nil
}

// cleanDeviceGroupName trims and bounds a device group display name.
func cleanDeviceGroupName(name string) (string, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" || len([]rune(trimmed)) > maxGroupNameLen {
		return "", ErrInvalidDeviceGroupName
	}
	return trimmed, nil
}

// ensureDeviceGroupNameFree rejects a name already used by another device group
// of the organization, folding case in Go so all three dialects agree.
func ensureDeviceGroupNameFree(db *gorm.DB, orgID uint, name string, exceptID uint) error {
	var existing []model.DeviceGroup
	if err := store.ScopedByOrg(db, orgID).
		Select("id", "name").Find(&existing).Error; err != nil {
		return err
	}
	for _, group := range existing {
		if exceptID != 0 && group.ID == exceptID {
			continue
		}
		if strings.EqualFold(group.Name, name) {
			return ErrDeviceGroupNameTaken
		}
	}
	return nil
}

// validateDevices rejects the whole request when any requested device has no
// row in the organization.
func validateDevices(tx *gorm.DB, orgID uint, ids []uint) error {
	if len(ids) == 0 {
		return nil
	}
	var found []uint
	if err := store.ScopedByOrg(tx, orgID).Model(&model.Device{}).
		Where("id IN ?", ids).Pluck("id", &found).Error; err != nil {
		return err
	}
	if len(found) != len(ids) {
		return ErrInvalidDevice
	}
	return nil
}

// mapDeviceGroupNameConflict translates a unique-index violation into the
// domain error the handler maps onto 409, with a string fallback for drivers
// that have no ErrorTranslator (the SQLite driver).
func mapDeviceGroupNameConflict(err error) error {
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return ErrDeviceGroupNameTaken
	}
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "unique") || strings.Contains(lower, "duplicate") {
		return ErrDeviceGroupNameTaken
	}
	return err
}
