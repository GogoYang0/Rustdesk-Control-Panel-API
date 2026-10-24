package model

import "time"

// Organization is the tenant root. Every business row carries its ID.
type Organization struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Name      string    `gorm:"size:128;not null" json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// ProvisioningDisabled records an explicit deprovision. Without it the
	// reconciler would see an organization without a server group and deploy
	// hbbs/hbbr again right after the operator removed them.
	ProvisioningDisabled bool `gorm:"not null;default:false" json:"provisioning_disabled"`
}

// Role values inside an organization.
const (
	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleMember = "member"
)

// Membership links a user to an organization with an in-org role.
//
// RoleID is the authorization source: it points at a Role row of the same
// organization (builtin or custom). Role is the legacy string kept for a staged
// migration only — after MigrateRoles runs it is no longer read.
//
// A disabled membership blocks management and compat authentication for that
// organization without deleting the row: history (devices, sessions, audits)
// stays attributable, and re-enabling restores access.
type Membership struct {
	ID             uint       `gorm:"primaryKey" json:"id"`
	OrganizationID uint       `gorm:"uniqueIndex:idx_membership_org_user;not null" json:"organization_id"`
	UserID         uint       `gorm:"uniqueIndex:idx_membership_org_user;not null" json:"user_id"`
	RoleID         uint       `gorm:"not null;default:0;index" json:"role_id"`
	Role           string     `gorm:"size:16;not null" json:"role"`
	Disabled       bool       `gorm:"not null;default:false" json:"disabled"`
	DisabledAt     *time.Time `json:"disabled_at,omitempty"`
	DisabledBy     uint       `gorm:"not null;default:0" json:"disabled_by,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}
