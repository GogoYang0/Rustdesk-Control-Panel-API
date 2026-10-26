package authz

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// Role error sentinels. Handlers map them onto 400/404/409 responses.
var (
	// ErrRoleNotFound reports a role id/name that does not exist in the tenant.
	ErrRoleNotFound = errors.New("role not found")
	// ErrRoleBuiltin reports an attempt to edit or delete a seeded role.
	ErrRoleBuiltin = errors.New("builtin role cannot be modified")
	// ErrRoleNameTaken reports a name reserved by a builtin or used by another
	// role of the same organization.
	ErrRoleNameTaken = errors.New("role name is reserved or already in use")
	// ErrRoleInUse reports a custom role still referenced by memberships.
	ErrRoleInUse = errors.New("role is still assigned to members")
	// ErrInvalidRoleName reports an empty or overlong display name.
	ErrInvalidRoleName = errors.New("invalid role name")
	// ErrInvalidAuditScope reports an audit scope outside global/individual.
	ErrInvalidAuditScope = errors.New("invalid audit scope")
)

// maxRoleNameLen matches the size:64 column of model.Role.
const maxRoleNameLen = 64

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
//
// Once MigrateDropLegacyRole has removed memberships.role, the string backfill
// has nothing left to read: the builtins are still seeded (they are what the
// organization needs to authorize anyone) and the mapping loop is skipped.
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
		hasLegacyColumn := tx.Migrator().HasColumn(&model.Membership{}, "role")
		var orgIDs []uint
		if err := tx.Model(&model.Organization{}).Order("id").Pluck("id", &orgIDs).Error; err != nil {
			return fmt.Errorf("list organizations: %w", err)
		}
		for _, orgID := range orgIDs {
			if err := (&RoleService{}).EnsureBuiltinsTx(tx, orgID); err != nil {
				return fmt.Errorf("seed builtin roles for organization %d: %w", orgID, err)
			}
			if !hasLegacyColumn {
				continue
			}
			var members []model.Membership
			if err := store.ScopedByOrg(tx, orgID).
				Where("role_id = 0").Find(&members).Error; err != nil {
				return fmt.Errorf("list memberships of organization %d: %w", orgID, err)
			}
			for _, m := range members {
				// The legacy column is read outside the tenant scope and
				// filtered by organization explicitly: this is the cross-tenant
				// migration loop, and a tenant-scoped handle without a tenant
				// context would inject an empty condition and silently read
				// nothing.
				var legacy []string
				if err := store.WithoutTenantScope(tx).Table("memberships").
					Where("id = ? AND organization_id = ?", m.ID, orgID).
					Pluck("role", &legacy).Error; err != nil {
					return fmt.Errorf("read legacy role of membership %d: %w", m.ID, err)
				}
				legacyRole := ""
				if len(legacy) > 0 {
					legacyRole = legacy[0]
				}
				role, err := RoleByNameTx(tx, orgID, legacyRole)
				if err != nil {
					return fmt.Errorf("membership %d has unknown role %q: %w", m.ID, legacyRole, ErrUnknownLegacyRole)
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

// MigrateAccessPermission rewrites the builtin owner/admin permission sets of
// every organization to the current catalog on every startup.
//
// Permission sets are stored as JSON in roles.permissions, so extending the
// catalog alone leaves existing rows behind: every established admin would get
// 403 from the access-control endpoints. The rewrite is convergent rather than
// one-shot — an organization whose rows were written before access.manage
// existed (a restored database, an import) is upgraded on the next run instead
// of being skipped by a marker forever. Custom roles are never touched, and a
// failure aborts startup with the transaction rolled back.
func MigrateAccessPermission(db *gorm.DB) error {
	return db.Transaction(func(tx *gorm.DB) error {
		var orgIDs []uint
		if err := tx.Model(&model.Organization{}).Order("id").Pluck("id", &orgIDs).Error; err != nil {
			return fmt.Errorf("list organizations: %w", err)
		}
		for _, orgID := range orgIDs {
			for _, kind := range []string{model.RoleKindOwner, model.RoleKindAdmin} {
				role, err := ensureBuiltinTx(tx, orgID, kind)
				if err != nil {
					return fmt.Errorf("ensure builtin %s role for organization %d: %w", kind, orgID, err)
				}
				raw := *role
				if err := raw.SetPermissions(BuiltinPermissions(kind)); err != nil {
					return fmt.Errorf("encode %s permissions: %w", kind, err)
				}
				if err := store.ScopedByOrg(tx, orgID).Model(&model.Role{}).
					Where("id = ? AND kind = ?", role.ID, kind).
					Update("permissions", raw.Permissions).Error; err != nil {
					return fmt.Errorf("backfill %s permissions for organization %d: %w", kind, orgID, err)
				}
			}
		}
		return nil
	})
}

// RoleByIDTx returns a role of the tenant on the caller's transaction.
func RoleByIDTx(tx *gorm.DB, orgID, roleID uint) (*model.Role, error) {
	var role model.Role
	if err := store.ScopedByOrg(tx, orgID).First(&role, roleID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrRoleNotFound
		}
		return nil, err
	}
	return &role, nil
}

// ResolvableRoleIDs returns the subquery of role ids that exist in this
// organization, for use as `role_id IN (?)`.
//
// Judging a membership by "role_id <> 0" alone is not enough: a concurrent role
// deletion can leave a dangling role_id behind (DeleteCustomTx counts
// references without holding the role assignment path's lock), and such a
// membership authorizes nothing — authz resolution fails closed — so it must
// contribute nothing to rule evaluation either. The set is rendered as a
// subquery inside the caller's statement, so the role set and the membership
// rows are read by one query instead of two reads that a concurrent deletion
// can straddle. A subquery built through ScopedByOrg carries the tenant context
// the plugin injects, so it never crosses organizations.
func ResolvableRoleIDs(db *gorm.DB, orgID uint) *gorm.DB {
	return store.ScopedByOrg(db, orgID).Model(&model.Role{}).Select("id")
}

// List returns every role of the organization, builtins first (seed order) and
// custom roles after.
func (s *RoleService) List(orgID uint) ([]model.Role, error) {
	var roles []model.Role
	if err := store.ScopedByOrg(s.db, orgID).Order("id").Find(&roles).Error; err != nil {
		return nil, err
	}
	return roles, nil
}

// CreateCustomTx validates and inserts a custom role on the caller's
// transaction. The caller records the audit entry in the same transaction.
func (s *RoleService) CreateCustomTx(tx *gorm.DB, orgID uint, name string, permissions []string, auditScope string) (*model.Role, error) {
	name, err := cleanRoleName(name)
	if err != nil {
		return nil, err
	}
	perms, err := NormalizePermissions(permissions)
	if err != nil {
		return nil, err
	}
	if err := ValidateDelegable(perms); err != nil {
		return nil, err
	}
	scope, err := cleanAuditScope(auditScope)
	if err != nil {
		return nil, err
	}
	if _, err := RoleByNameTx(tx, orgID, name); err == nil {
		return nil, ErrRoleNameTaken
	} else if !errors.Is(err, ErrRoleNotFound) {
		return nil, err
	}

	role := model.Role{
		OrganizationID: orgID,
		Name:           name,
		Kind:           model.RoleKindCustom,
		AuditScope:     scope,
	}
	if err := role.SetPermissions(perms); err != nil {
		return nil, err
	}
	if err := store.ScopedByOrg(tx, orgID).Create(&role).Error; err != nil {
		return nil, err
	}
	return &role, nil
}

// UpdateCustomTx replaces a custom role's name, permission set and audit scope.
func (s *RoleService) UpdateCustomTx(tx *gorm.DB, orgID, roleID uint, name string, permissions []string, auditScope string) (*model.Role, error) {
	role, err := RoleByIDTx(tx, orgID, roleID)
	if err != nil {
		return nil, err
	}
	if role.Builtin() {
		return nil, ErrRoleBuiltin
	}
	name, err = cleanRoleName(name)
	if err != nil {
		return nil, err
	}
	perms, err := NormalizePermissions(permissions)
	if err != nil {
		return nil, err
	}
	if err := ValidateDelegable(perms); err != nil {
		return nil, err
	}
	scope, err := cleanAuditScope(auditScope)
	if err != nil {
		return nil, err
	}
	if other, err := RoleByNameTx(tx, orgID, name); err == nil && other.ID != role.ID {
		return nil, ErrRoleNameTaken
	} else if err != nil && !errors.Is(err, ErrRoleNotFound) {
		return nil, err
	}

	raw := *role
	raw.Name = name
	raw.AuditScope = scope
	if err := raw.SetPermissions(perms); err != nil {
		return nil, err
	}
	res := store.ScopedByOrg(tx, orgID).Model(&model.Role{}).
		Where("id = ? AND kind = ?", role.ID, model.RoleKindCustom).
		Updates(map[string]any{
			"name":        raw.Name,
			"permissions": raw.Permissions,
			"audit_scope": raw.AuditScope,
		})
	if res.Error != nil {
		return nil, res.Error
	}
	// RowsAffected may be 0 on MySQL when the update is a no-op; the role row
	// was read above, so the re-read below decides whether it still exists.
	updated, err := RoleByIDTx(tx, orgID, role.ID)
	if err != nil {
		return nil, err
	}
	return updated, nil
}

// DeleteCustomTx deletes an unreferenced custom role. Builtin roles and roles
// still assigned to a membership are refused.
func (s *RoleService) DeleteCustomTx(tx *gorm.DB, orgID, roleID uint) error {
	role, err := RoleByIDTx(tx, orgID, roleID)
	if err != nil {
		return err
	}
	if role.Builtin() {
		return ErrRoleBuiltin
	}
	var inUse int64
	if err := store.ScopedByOrg(tx, orgID).Model(&model.Membership{}).
		Where("role_id = ?", role.ID).Count(&inUse).Error; err != nil {
		return err
	}
	if inUse > 0 {
		return ErrRoleInUse
	}
	res := store.ScopedByOrg(tx, orgID).Delete(&model.Role{}, role.ID)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrRoleNotFound
	}
	return nil
}

// cleanRoleName trims and bounds a role display name.
func cleanRoleName(name string) (string, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" || len([]rune(trimmed)) > maxRoleNameLen {
		return "", ErrInvalidRoleName
	}
	return trimmed, nil
}

// cleanAuditScope defaults an omitted scope to individual and rejects values
// outside the two contract values.
func cleanAuditScope(scope string) (string, error) {
	switch scope {
	case "":
		return model.AuditScopeIndividual, nil
	case model.AuditScopeGlobal, model.AuditScopeIndividual:
		return scope, nil
	default:
		return "", ErrInvalidAuditScope
	}
}
