package model

import "time"

// Organization is the tenant root. Every business row carries its ID.
type Organization struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Name      string    `gorm:"size:128;not null" json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Role values inside an organization.
const (
	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleMember = "member"
)

// Membership links a user to an organization with an in-org role.
type Membership struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	OrganizationID uint      `gorm:"uniqueIndex:idx_membership_org_user;not null" json:"organization_id"`
	UserID         uint      `gorm:"uniqueIndex:idx_membership_org_user;not null" json:"user_id"`
	Role           string    `gorm:"size:16;not null" json:"role"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}
