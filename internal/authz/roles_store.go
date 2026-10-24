package authz

import (
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// ErrRoleNotFound reports a role id/name that does not exist in the tenant.
var ErrRoleNotFound = errors.New("role not found")

// RoleService owns the organization-scoped role rows: seeding the builtin
// roles, resolving a membership's effective role, and the one-time backfill of
// the legacy role strings.
type RoleService struct {
	db *gorm.DB
}

// NewRoleService builds the service. The database handle is unscoped; every
// statement goes through store.ScopedByOrg.
func NewRoleService(db *gorm.DB) *RoleService {
	return &RoleService{db: db}
}

// EnsureBuiltins seeds the three builtin roles for an organization. It is
// idempotent and safe to call from any write path that creates a membership.
func (s *RoleService) EnsureBuiltins(orgID uint) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		return s.EnsureBuiltinsTx(tx, orgID)
	})
}

// EnsureBuiltinsTx is EnsureBuiltins on the caller's transaction.
func (s *RoleService) EnsureBuiltinsTx(tx *gorm.DB, orgID uint) error {
	for _, kind := range []string{model.RoleKindOwner, model.RoleKindAdmin, model.RoleKindMember} {
		if _, err := ensureBuiltinTx(tx, orgID, kind); err != nil {
			return err
		}
	}
	return nil
}

// RoleByKindTx returns the builtin role row of one kind inside the tenant.
func RoleByKindTx(tx *gorm.DB, orgID uint, kind string) (*model.Role, error) {
	var role model.Role
	if err := store.ScopedByOrg(tx, orgID).Where("kind = ?", kind).First(&role).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrRoleNotFound
		}
		return nil, err
	}
	return &role, nil
}

// RoleByNameTx returns a role by its tenant-unique name.
func RoleByNameTx(tx *gorm.DB, orgID uint, name string) (*model.Role, error) {
	var role model.Role
	if err := store.ScopedByOrg(tx, orgID).Where("name = ?", name).First(&role).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrRoleNotFound
		}
		return nil, err
	}
	return &role, nil
}

// RoleByID returns a role of the tenant, or ErrRoleNotFound.
func (s *RoleService) RoleByID(orgID, roleID uint) (*model.Role, error) {
	var role model.Role
	if err := store.ScopedByOrg(s.db, orgID).First(&role, roleID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrRoleNotFound
		}
		return nil, err
	}
	return &role, nil
}

// Resolve returns the effective role of a membership. A zero role_id or a
// missing row fails closed with ErrRoleNotFound.
func (s *RoleService) Resolve(orgID uint, m model.Membership) (*model.Role, error) {
	if m.RoleID == 0 {
		return nil, ErrRoleNotFound
	}
	return s.RoleByID(orgID, m.RoleID)
}

func ensureBuiltinTx(tx *gorm.DB, orgID uint, kind string) (*model.Role, error) {
	if role, err := RoleByKindTx(tx, orgID, kind); err == nil {
		return role, nil
	} else if !errors.Is(err, ErrRoleNotFound) {
		return nil, err
	}

	scope := model.AuditScopeIndividual
	if kind == model.RoleKindOwner || kind == model.RoleKindAdmin {
		scope = model.AuditScopeGlobal
	}
	role := model.Role{
		OrganizationID: orgID,
		Name:           kind,
		Kind:           kind,
		AuditScope:     scope,
	}
	if err := role.SetPermissions(BuiltinPermissions(kind)); err != nil {
		return nil, err
	}
	// Two concurrent creators must converge on one row: the unique
	// (organization_id, name) index decides, and the loser re-reads.
	if err := store.ScopedByOrg(tx, orgID).
		Clauses(clause.OnConflict{DoNothing: true}).
		Create(&role).Error; err != nil {
		return nil, err
	}
	return RoleByKindTx(tx, orgID, kind)
}

// roleMigrationName is the one-shot marker of the legacy-role backfill.
const roleMigrationName = "2026-10-24-m4-roles"

// MigrateRoles seeds builtin roles for every organization and maps each
// membership's legacy role string onto its role_id. Unknown role strings abort
// the migration (fail closed) instead of silently demoting members; the marker
// is written only on success, so a crashed startup retries the backfill.
func MigrateRoles(db *gorm.DB) error {
	var mark model.MigrationMark
	err := db.Where("name = ?", roleMigrationName).First(&mark).Error
	if err == nil {
		return nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("look up role migration mark: %w", err)
	}

	return db.Transaction(func(tx *gorm.DB) error {
		var orgIDs []uint
		if err := tx.Model(&model.Organization{}).Order("id").Pluck("id", &orgIDs).Error; err != nil {
			return fmt.Errorf("list organizations: %w", err)
		}
		for _, orgID := range orgIDs {
			if err := (&RoleService{}).EnsureBuiltinsTx(tx, orgID); err != nil {
				return fmt.Errorf("seed builtin roles for organization %d: %w", orgID, err)
			}
			var members []model.Membership
			if err := store.ScopedByOrg(tx, orgID).
				Where("role_id = 0").Find(&members).Error; err != nil {
				return fmt.Errorf("list memberships of organization %d: %w", orgID, err)
			}
			for _, m := range members {
				role, err := RoleByNameTx(tx, orgID, m.Role)
				if err != nil {
					return fmt.Errorf("membership %d has unknown role %q: %w", m.ID, m.Role, ErrUnknownLegacyRole)
				}
				if err := store.ScopedByOrg(tx, orgID).
					Model(&model.Membership{}).
					Where("id = ?", m.ID).
					Update("role_id", role.ID).Error; err != nil {
					return fmt.Errorf("backfill membership %d: %w", m.ID, err)
				}
			}
		}
		return tx.Create(&model.MigrationMark{
			Name:      roleMigrationName,
			AppliedAt: time.Now().UTC(),
		}).Error
	})
}

// ErrUnknownLegacyRole reports a membership whose legacy role string matches no
// builtin role.
var ErrUnknownLegacyRole = errors.New("unknown legacy role")
