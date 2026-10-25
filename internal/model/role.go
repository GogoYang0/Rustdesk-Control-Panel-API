package model

import (
	"encoding/json"
	"time"
)

// Role kinds. Builtin kinds are seeded per organization and immutable; custom
// roles are org-defined permission sets assignable to memberships.
const (
	RoleKindOwner  = "owner"
	RoleKindAdmin  = "admin"
	RoleKindMember = "member"
	RoleKindCustom = "custom"
)

// Audit visibility scopes carried by a role.
const (
	AuditScopeGlobal     = "global"
	AuditScopeIndividual = "individual"
)

// Role is an organization-scoped permission set. Membership.RoleID is the only
// authorization source; the legacy Membership.Role string is kept for staged
// migration only and is no longer read.
type Role struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	OrganizationID uint      `gorm:"not null;uniqueIndex:idx_role_org_name,priority:1" json:"organization_id"`
	Name           string    `gorm:"size:64;not null;uniqueIndex:idx_role_org_name,priority:2" json:"name"`
	Kind           string    `gorm:"size:16;not null" json:"kind"`
	Permissions    string    `gorm:"type:text;not null" json:"permissions"`
	AuditScope     string    `gorm:"size:16;not null" json:"audit_scope"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// PermissionList decodes the stored permission codes. A malformed value yields
// an empty set: authorization fails closed rather than granting anything.
func (r Role) PermissionList() []string {
	if r.Permissions == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(r.Permissions), &out); err != nil {
		return nil
	}
	return out
}

// SetPermissions encodes the codes into the stored form.
func (r *Role) SetPermissions(codes []string) error {
	if codes == nil {
		codes = []string{}
	}
	raw, err := json.Marshal(codes)
	if err != nil {
		return err
	}
	r.Permissions = string(raw)
	return nil
}

// Builtin reports whether the role is one of the immutable seeded roles.
func (r *Role) Builtin() bool {
	return r != nil && r.Kind != RoleKindCustom
}
