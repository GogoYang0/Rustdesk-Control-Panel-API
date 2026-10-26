package controlrole

import (
	"encoding/json"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// Migrate seeds the built-in default role for every organization that lacks
// one. It runs on every startup and must therefore be idempotent: a fresh boot
// must not create a second default row, and two nodes booting together must not
// race one into existence twice.
//
// The unique index on (organization_id, name) is what makes the concurrent case
// safe — the insert is issued with ON CONFLICT DO NOTHING, so the loser's write
// is a no-op rather than an error.
func Migrate(db *gorm.DB, now func() time.Time) error {
	var orgIDs []uint
	if err := db.Model(&model.Organization{}).Pluck("id", &orgIDs).Error; err != nil {
		return err
	}
	if len(orgIDs) == 0 {
		return nil
	}

	blob, err := json.Marshal(DefaultPermissions())
	if err != nil {
		return err
	}

	for _, orgID := range orgIDs {
		// Every statement carries the organization scope explicitly: the tenant
		// plugin rewrites unscoped queries on control_roles to WHERE 1=0, so a
		// bare Count would always read zero and a bare Create would be refused.
		scoped := store.ScopedByOrg(db, orgID)
		var existing int64
		if err := scoped.Model(&model.ControlRole{}).
			Where("kind = ?", model.KindControlRoleDefault).
			Count(&existing).Error; err != nil {
			return err
		}
		if existing > 0 {
			continue
		}
		role := model.ControlRole{
			OrganizationID:  orgID,
			Name:            DefaultRoleName,
			Kind:            model.KindControlRoleDefault,
			PermissionsJSON: string(blob),
			CreatedAt:       now(),
			UpdatedAt:       now(),
		}
		if err := scoped.Clauses(clause.OnConflict{DoNothing: true}).Create(&role).Error; err != nil {
			return err
		}
	}
	return nil
}
