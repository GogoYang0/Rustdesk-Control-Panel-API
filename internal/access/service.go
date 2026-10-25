// Package access owns the access-control domain: user groups, device groups
// and the allow-only rules that decide which devices a member can see and
// reach. The same evaluation gates the compat peer list and ticket issue and
// redemption, so visibility and reachability never disagree.
package access

import (
	"errors"
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

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
