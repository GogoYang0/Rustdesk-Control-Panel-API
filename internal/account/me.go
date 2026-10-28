// Package account resolves the caller's own identity and organization roles for
// the console's first paint. It is deliberately read-only: nothing here writes,
// audits or caches.
package account

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

var (
	ErrInvalidInput = errors.New("invalid account input")
	ErrNotFound     = errors.New("user not found")
)

// Service answers "who am I" without going through a per-organization request.
type Service struct {
	db    *gorm.DB
	roles *authz.RoleService
}

func NewService(db *gorm.DB, roles *authz.RoleService) *Service {
	return &Service{db: db, roles: roles}
}

// MeUser is the caller's own profile. It never carries the password hash, the
// TOTP secret or any token.
type MeUser struct {
	ID            uint   `json:"id"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	TOTPEnabled   bool   `json:"totp_enabled"`
	HasPassword   bool   `json:"has_password"`
}

// MeOrg is one effective membership: the organization, the role behind it and
// that role's permission codes.
type MeOrg struct {
	ID          uint     `json:"id"`
	Name        string   `json:"name"`
	RoleID      uint     `json:"role_id"`
	RoleKind    string   `json:"role_kind"`
	Permissions []string `json:"permissions"`
}

type Me struct {
	User MeUser  `json:"user"`
	Orgs []MeOrg `json:"orgs"`
}

// Me returns the user's profile and every organization in which the user holds
// an effective membership.
//
// Two kinds of membership are omitted rather than reported with an empty
// permission set: a disabled one, and one whose role_id does not resolve. Both
// authorize nothing on every request path, so listing them would tell the
// console the user still belongs to the organization — the console would then
// render pages that 403 on the first call.
func (s *Service) Me(ctx context.Context, userID uint) (Me, error) {
	if userID == 0 {
		return Me{}, fmt.Errorf("%w: user is required", ErrInvalidInput)
	}
	db := s.db.WithContext(ctx)

	var user model.User
	if err := db.First(&user, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return Me{}, ErrNotFound
		}
		return Me{}, err
	}

	var totp model.UserTOTP
	totpEnabled := false
	switch err := db.First(&totp, userID).Error; {
	case err == nil:
		totpEnabled = totp.EnabledAt != nil
	case !errors.Is(err, gorm.ErrRecordNotFound):
		return Me{}, err
	}

	var memberships []model.Membership
	if err := store.WithoutTenantScope(db).
		Where("user_id = ? AND disabled = ?", userID, false).
		Order("organization_id").
		Find(&memberships).Error; err != nil {
		return Me{}, err
	}

	me := Me{
		User: MeUser{
			ID:            user.ID,
			Email:         user.Email,
			EmailVerified: user.EmailVerified,
			TOTPEnabled:   totpEnabled,
			// The passkey-only sentinel (5b-1) is an empty password hash.
			HasPassword: user.PasswordHash != "",
		},
		Orgs: make([]MeOrg, 0, len(memberships)),
	}
	if len(memberships) == 0 {
		return me, nil
	}

	// Organization names in one round trip. The role resolution below is still
	// one query per organization, which the per-user organization quota keeps
	// bounded; folding it into a join would mean duplicating the role-resolution
	// rules that authz owns.
	ids := make([]uint, 0, len(memberships))
	for _, m := range memberships {
		ids = append(ids, m.OrganizationID)
	}
	var orgRows []model.Organization
	if err := store.WithoutTenantScope(db).Select("id", "name").
		Where("id IN ?", ids).Find(&orgRows).Error; err != nil {
		return Me{}, err
	}
	names := make(map[uint]string, len(orgRows))
	for _, org := range orgRows {
		names[org.ID] = org.Name
	}

	for _, m := range memberships {
		role, err := s.roles.Resolve(m.OrganizationID, m)
		if err != nil {
			continue
		}
		name, ok := names[m.OrganizationID]
		if !ok {
			continue
		}
		perms := role.PermissionList()
		if perms == nil {
			perms = []string{}
		}
		me.Orgs = append(me.Orgs, MeOrg{
			ID:          m.OrganizationID,
			Name:        name,
			RoleID:      role.ID,
			RoleKind:    role.Kind,
			Permissions: perms,
		})
	}
	return me, nil
}
