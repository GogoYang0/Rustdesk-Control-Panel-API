package controlrole

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// maxNameLen mirrors the contract's 64-rune limit.
const maxNameLen = 64

// Domain errors. Handlers map them onto 400/403/404/409.
var (
	ErrInvalidName            = errors.New("invalid control role name")
	ErrDuplicateName          = errors.New("control role name already exists")
	ErrNotFound               = errors.New("control role not found")
	ErrBuiltinImmutable       = errors.New("built-in control role cannot be renamed or deleted")
	ErrUnknownPermissionKey   = errors.New("unknown permission key")
	ErrInvalidPermissionState = errors.New("invalid permission state")
	// ErrUnaudited reports a mutation attempted without a transactional
	// recorder: an unaudited role change is worse than a refused one.
	ErrUnaudited = errors.New("control role mutations require an audit recorder")
)

// Normalize validates every key and state, drops duplicates and fills missing
// keys with use_client. A nil map normalizes to the all-use_client default, so
// callers never store a partial map that would later read as "unknown".
func (p Permissions) Normalize() (Permissions, error) {
	out := make(Permissions, len(keys))
	for k, v := range p {
		switch v {
		case StateUseClient, StateEnable, StateDisable:
		default:
			return nil, fmt.Errorf("%w: %s=%q", ErrInvalidPermissionState, k, v)
		}
		known := false
		for _, key := range keys {
			if key == k {
				known = true
				break
			}
		}
		if !known {
			return nil, fmt.Errorf("%w: %s", ErrUnknownPermissionKey, k)
		}
		out[k] = v
	}
	for _, k := range keys {
		if _, ok := out[k]; !ok {
			out[k] = StateUseClient
		}
	}
	return out, nil
}

// Mask renders the set as RustDesk's ControlPermissions bitmask. Only explicit
// enables set a bit: "use_client" and "disable" both leave it clear, which is
// why the full tri-state is stored alongside it.
func (p Permissions) Mask() uint64 {
	var mask uint64
	for i, k := range keys {
		if p[k] == StateEnable {
			mask |= 1 << uint(i)
		}
	}
	return mask
}

// Service owns control roles and their assignments.
type Service struct {
	db       *gorm.DB
	recorder audit.TxRecorder
	now      func() time.Time
}

// NewService wires the service. A nil recorder makes every mutation fail
// closed (ErrUnaudited); production always injects one.
func NewService(db *gorm.DB, recorder audit.TxRecorder, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{db: db, recorder: recorder, now: now}
}

// List returns the organization's roles, default first.
func (s *Service) List(ctx context.Context, orgID uint) ([]model.ControlRole, error) {
	var roles []model.ControlRole
	err := store.ScopedByOrg(s.db.WithContext(ctx), orgID).
		Order("kind DESC").Order("name").Find(&roles).Error
	return roles, err
}

// Create adds a custom role. Unknown permission keys or states reject the whole
// request instead of storing a partially-valid row.
func (s *Service) Create(ctx context.Context, orgID, actorID uint, name string, perms Permissions) (*model.ControlRole, error) {
	if s.recorder == nil {
		return nil, ErrUnaudited
	}
	name, err := normalizeName(name)
	if err != nil {
		return nil, err
	}
	normalized, err := perms.Normalize()
	if err != nil {
		return nil, err
	}
	blob, err := json.Marshal(normalized)
	if err != nil {
		return nil, err
	}

	var role model.ControlRole
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		scoped := store.ScopedByOrg(tx, orgID)
		if taken, terr := roleNameTaken(scoped, name, 0); terr != nil {
			return terr
		} else if taken {
			return ErrDuplicateName
		}
		role = model.ControlRole{
			OrganizationID:  orgID,
			Name:            name,
			Kind:            model.KindControlRoleCustom,
			PermissionsJSON: string(blob),
			CreatedAt:       s.now(),
			UpdatedAt:       s.now(),
		}
		if cerr := scoped.Create(&role).Error; cerr != nil {
			// A concurrent create may have won between the check and the
			// insert; report it as the name conflict it is.
			if taken, _ := roleNameTaken(scoped, name, 0); taken {
				return ErrDuplicateName
			}
			return cerr
		}
		return s.recorder.RecordTx(tx, audit.Entry{
			OrganizationID: orgID,
			ActorUserID:    actorID,
			Action:         "control_role.create",
			TargetType:     "control_role",
			TargetID:       strconv.FormatUint(uint64(role.ID), 10),
			Detail:         map[string]any{"name": role.Name},
		})
	})
	if err != nil {
		return nil, err
	}
	return &role, nil
}

// Update changes a role's name and/or permissions. The built-in default role
// may change its permissions but never its name: the seed and the "unassigned
// members fall back to it" contract both key off that row.
func (s *Service) Update(ctx context.Context, orgID, actorID, roleID uint, name *string, perms *Permissions) (*model.ControlRole, error) {
	if s.recorder == nil {
		return nil, ErrUnaudited
	}
	var updated model.ControlRole
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		scoped := store.ScopedByOrg(tx, orgID)
		var role model.ControlRole
		if err := scoped.First(&role, roleID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		updates := map[string]any{"updated_at": s.now()}
		if name != nil {
			clean, nerr := normalizeName(*name)
			if nerr != nil {
				return nerr
			}
			if role.Kind == model.KindControlRoleDefault && clean != role.Name {
				return ErrBuiltinImmutable
			}
			if clean != role.Name {
				if taken, terr := roleNameTaken(scoped, clean, role.ID); terr != nil {
					return terr
				} else if taken {
					return ErrDuplicateName
				}
			}
			updates["name"] = clean
		}
		if perms != nil {
			normalized, nerr := perms.Normalize()
			if nerr != nil {
				return nerr
			}
			blob, merr := json.Marshal(normalized)
			if merr != nil {
				return merr
			}
			updates["permissions_json"] = string(blob)
		}
		if err := scoped.Model(&model.ControlRole{}).Where("id = ?", role.ID).Updates(updates).Error; err != nil {
			return err
		}
		if err := scoped.First(&updated, role.ID).Error; err != nil {
			return err
		}
		detail := map[string]any{"name": updated.Name}
		if perms != nil {
			detail["permissions"] = updated.PermissionsJSON
		}
		return s.recorder.RecordTx(tx, audit.Entry{
			OrganizationID: orgID,
			ActorUserID:    actorID,
			Action:         "control_role.update",
			TargetType:     "control_role",
			TargetID:       strconv.FormatUint(uint64(role.ID), 10),
			Detail:         detail,
		})
	})
	if err != nil {
		return nil, err
	}
	return &updated, nil
}

// Delete removes a custom role and clears the assignment on every member that
// held it, in one transaction: a dangling control_role_id would otherwise read
// as "unassigned" while still pointing at a missing row.
func (s *Service) Delete(ctx context.Context, orgID, actorID, roleID uint) error {
	if s.recorder == nil {
		return ErrUnaudited
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		scoped := store.ScopedByOrg(tx, orgID)
		var role model.ControlRole
		if err := scoped.First(&role, roleID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if role.Kind == model.KindControlRoleDefault {
			return ErrBuiltinImmutable
		}
		if err := scoped.Model(&model.Membership{}).
			Where("control_role_id = ?", role.ID).
			Update("control_role_id", nil).Error; err != nil {
			return err
		}
		if err := scoped.Delete(&model.ControlRole{}, role.ID).Error; err != nil {
			return err
		}
		return s.recorder.RecordTx(tx, audit.Entry{
			OrganizationID: orgID,
			ActorUserID:    actorID,
			Action:         "control_role.delete",
			TargetType:     "control_role",
			TargetID:       strconv.FormatUint(uint64(role.ID), 10),
			Detail:         map[string]any{"name": role.Name},
		})
	})
}

// Assign sets (or clears, when roleID is nil) a member's control role. The
// target must be a member of this organization and the role must belong to it;
// both are checked through the tenant scope, so a foreign id reads as missing.
func (s *Service) Assign(ctx context.Context, orgID, actorID, targetUserID uint, roleID *uint) error {
	if s.recorder == nil {
		return ErrUnaudited
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		scoped := store.ScopedByOrg(tx, orgID)
		var membership model.Membership
		if err := scoped.Where("user_id = ?", targetUserID).First(&membership).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if roleID != nil {
			var role model.ControlRole
			if err := scoped.First(&role, *roleID).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return ErrNotFound
				}
				return err
			}
		}
		if err := scoped.Model(&model.Membership{}).
			Where("id = ?", membership.ID).
			Update("control_role_id", roleID).Error; err != nil {
			return err
		}
		detail := map[string]any{"user_id": targetUserID}
		if roleID != nil {
			detail["role_id"] = *roleID
		}
		return s.recorder.RecordTx(tx, audit.Entry{
			OrganizationID: orgID,
			ActorUserID:    actorID,
			Action:         "control_role.assign",
			TargetType:     "membership",
			TargetID:       strconv.FormatUint(uint64(membership.ID), 10),
			Detail:         detail,
		})
	})
}

// EffectiveFor resolves the permissions that apply to one member and returns
// them with their bitmask and the role id they came from. A missing membership,
// a nil assignment, a deleted role or an unreadable payload all fall back to the
// default role: control roles never decide whether a connection is allowed, so
// degrading to "override nothing" is the safe answer.
func (s *Service) EffectiveFor(ctx context.Context, orgID, userID uint) (Permissions, uint64, *uint, error) {
	scoped := store.ScopedByOrg(s.db.WithContext(ctx), orgID)

	var membership model.Membership
	roleID := uint(0)
	if err := scoped.Where("user_id = ?", userID).First(&membership).Error; err == nil {
		if membership.ControlRoleID != nil {
			roleID = *membership.ControlRoleID
		}
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, 0, nil, err
	}

	if roleID == 0 {
		def, err := defaultRole(scoped)
		if err != nil {
			return nil, 0, nil, err
		}
		perms := decodeOrEmpty(def)
		return perms, perms.Mask(), &def.ID, nil
	}

	var role model.ControlRole
	if err := scoped.First(&role, roleID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			def, derr := defaultRole(scoped)
			if derr != nil {
				return nil, 0, nil, derr
			}
			perms := decodeOrEmpty(def)
			return perms, perms.Mask(), &def.ID, nil
		}
		return nil, 0, nil, err
	}
	perms := decodeOrEmpty(role)
	return perms, perms.Mask(), &role.ID, nil
}

func defaultRole(scoped *gorm.DB) (model.ControlRole, error) {
	var role model.ControlRole
	err := scoped.Where("kind = ?", model.KindControlRoleDefault).First(&role).Error
	return role, err
}

// decodeOrEmpty parses the stored tri-state map. Unreadable JSON degrades to
// "override nothing" instead of failing the caller.
func decodeOrEmpty(role model.ControlRole) Permissions {
	var perms Permissions
	if err := json.Unmarshal([]byte(role.PermissionsJSON), &perms); err != nil {
		return DefaultPermissions()
	}
	normalized, err := perms.Normalize()
	if err != nil {
		return DefaultPermissions()
	}
	return normalized
}

func roleNameTaken(scoped *gorm.DB, name string, excludeID uint) (bool, error) {
	q := scoped.Model(&model.ControlRole{}).Where("name = ?", name)
	if excludeID != 0 {
		q = q.Where("id <> ?", excludeID)
	}
	var count int64
	if err := q.Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}

func normalizeName(name string) (string, error) {
	clean := strings.TrimSpace(name)
	if clean == "" || utf8.RuneCountInString(clean) > maxNameLen {
		return "", ErrInvalidName
	}
	return clean, nil
}
