package model

import "time"

// Control role kinds. Exactly one default role exists per organization and it
// cannot be deleted or renamed; custom roles are entirely administrator-owned.
const (
	KindControlRoleDefault = "default"
	KindControlRoleCustom  = "custom"
)

// ControlRole is an organization-scoped set of in-session permissions.
//
// PermissionsJSON holds the fourteen keys of RustDesk's ControlPermissions
// enum mapped to one of three states ("use_client", "enable", "disable").
// Stored as text because the payload is read and written whole: nothing queries
// by individual permission, and a JSON object keeps the tri-state readable
// without a second table.
//
// It does NOT restrict native RustDesk sessions: hbbs injects
// ControlPermissions into its signalling messages, and this panel is not in the
// signalling path (design D10). The panel-issued ticket snapshot is the only
// place the value travels today.
type ControlRole struct {
	ID             uint   `gorm:"primaryKey" json:"id"`
	OrganizationID uint   `gorm:"uniqueIndex:idx_control_role_org_name,priority:1;not null" json:"organization_id"`
	Name           string `gorm:"size:64;uniqueIndex:idx_control_role_org_name,priority:2;not null" json:"name"`
	// Kind is "default" or "custom"; the default row is seeded per organization.
	Kind string `gorm:"size:16;not null;index" json:"kind"`
	// PermissionsJSON is a JSON object of permission key -> state.
	PermissionsJSON string    `gorm:"type:text;not null" json:"permissions"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}
