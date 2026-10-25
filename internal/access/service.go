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
func (s *Service) ListUserGroups(_ context.Context, orgID uint) ([]GroupView, error) {
	var groups []model.UserGroup
	if err := store.ScopedByOrg(s.db, orgID).Order("id").Find(&groups).Error; err != nil {
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
	if err := store.ScopedByOrg(s.db, orgID).
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

// CreateUserGroup adds a custom group. The reserved name is refused in any
// casing, and duplicate names are rejected before the insert.
func (s *Service) CreateUserGroup(_ context.Context, orgID, actorID uint, name string) (*model.UserGroup, error) {
	clean, err := cleanGroupName(name)
	if err != nil {
		return nil, err
	}
	var group model.UserGroup
	err = s.write(func(tx *gorm.DB) error {
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
func (s *Service) RenameUserGroup(_ context.Context, orgID, actorID, groupID uint, name string) (*model.UserGroup, error) {
	clean, err := cleanGroupName(name)
	if err != nil {
		return nil, err
	}
	var updated model.UserGroup
	err = s.write(func(tx *gorm.DB) error {
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
		if err := store.ScopedByOrg(tx, orgID).Model(&model.UserGroup{}).
			Where("id = ? AND kind = ?", group.ID, model.UserGroupKindCustom).
			Updates(map[string]any{"name": clean, "updated_at": s.now().UTC()}).Error; err != nil {
			return mapGroupNameConflict(err)
		}
		updated = *group
		updated.Name = clean
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
func (s *Service) DeleteUserGroup(_ context.Context, orgID, actorID, groupID uint) (int, error) {
	cascaded := 0
	err := s.write(func(tx *gorm.DB) error {
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
func (s *Service) ReplaceUserGroupMembers(_ context.Context, orgID, actorID, groupID uint, userIDs []uint) (removed, added int, err error) {
	wanted := dedupeIDs(userIDs)
	err = s.write(func(tx *gorm.DB) error {
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

// write runs fn inside one transaction, refusing to start without a
// transactional recorder so an unaudited group change can never commit.
func (s *Service) write(fn func(tx *gorm.DB) error) error {
	if s.recorder == nil {
		return ErrAuditUnavailable
	}
	return s.db.Transaction(fn)
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
// organization. The comparison is case-insensitive in the query so MySQL's
// collation and SQLite/PostgreSQL's byte ordering agree.
func ensureGroupNameFree(tx *gorm.DB, orgID uint, name string, exceptID uint) error {
	query := store.ScopedByOrg(tx, orgID).Model(&model.UserGroup{}).
		Where("LOWER(name) = ?", strings.ToLower(name))
	if exceptID != 0 {
		query = query.Where("id <> ?", exceptID)
	}
	var count int64
	if err := query.Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return ErrGroupNameTaken
	}
	return nil
}

// validateMembers rejects the whole request when any requested user has no
// membership in the organization (a foreign or nonexistent id).
func validateMembers(tx *gorm.DB, orgID uint, ids []uint) error {
	if len(ids) == 0 {
		return nil
	}
	var found []uint
	if err := store.ScopedByOrg(tx, orgID).Model(&model.Membership{}).
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
// error the handler maps onto 409.
func mapGroupNameConflict(err error) error {
	if errors.Is(err, gorm.ErrDuplicatedKey) {
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
