package controlrole

import (
	"encoding/json"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// EnsureDefaultsTx seeds the organization's built-in default role on the
// caller's transaction, so a freshly created organization has its fallback role
// the moment the create response returns. It is idempotent: a repeated call and
// two concurrent boots both end with exactly one default row.
func EnsureDefaultsTx(tx *gorm.DB, orgID uint) error {
	// Every statement carries the organization scope explicitly: the tenant
	// plugin rewrites unscoped queries on control_roles to WHERE 1=0, so a bare
	// Count would always read zero and a bare Create would be refused.
	scoped := store.ScopedByOrg(tx, orgID)
	var existing int64
	if err := scoped.Model(&model.ControlRole{}).
		Where("kind = ?", model.KindControlRoleDefault).
		Count(&existing).Error; err != nil {
		return err
	}
	if existing > 0 {
		return nil
	}
	blob, err := json.Marshal(DefaultPermissions())
	if err != nil {
		return err
	}
	now := time.Now()
	role := model.ControlRole{
		OrganizationID:  orgID,
		Name:            DefaultRoleName,
		Kind:            model.KindControlRoleDefault,
		PermissionsJSON: string(blob),
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	return scoped.Clauses(clause.OnConflict{DoNothing: true}).Create(&role).Error
}

// Migrate seeds the built-in default role for every organization that lacks one.
// It runs on every startup and must therefore be idempotent.
func Migrate(db *gorm.DB, now func() time.Time) error {
	_ = now // the seed stamps its own time; kept for the startup signature
	var orgIDs []uint
	if err := db.Model(&model.Organization{}).Order("id").Pluck("id", &orgIDs).Error; err != nil {
		return err
	}
	for _, orgID := range orgIDs {
		if err := EnsureDefaultsTx(db, orgID); err != nil {
			return err
		}
	}
	return nil
}
