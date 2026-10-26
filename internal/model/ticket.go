package model

import "time"

// Ticket is a one-shot connection ticket.
//
// Plaintext never touches the database: only TokenHash is stored, and the
// plaintext is returned exactly once in the issuance response. used_at is the
// one-shot marker, revoked_at is set by offboarding.
type Ticket struct {
	ID             uint  `gorm:"primaryKey" json:"id"`
	OrganizationID uint  `gorm:"not null;index:idx_ticket_org_device,priority:1" json:"organization_id"`
	DeviceID       uint  `gorm:"not null;index:idx_ticket_org_device,priority:2" json:"device_id"`
	ActorUserID    uint  `gorm:"index;not null" json:"actor_user_id"`
	ApprovalID     *uint `gorm:"index" json:"approval_id"`
	// TokenHash is the digest of the plaintext token; unique so a collision or
	// replay can never resolve to two tickets.
	TokenHash string `gorm:"size:64;not null;uniqueIndex" json:"-"`
	// PolicySnapshotJSON is the effective policy at issuance time, kept for
	// audit and troubleshooting after policies change or disappear. The JSON
	// suffix marks it as "marshal before use".
	PolicySnapshotJSON string `gorm:"type:text" json:"policy_snapshot"`
	// ControlRoleID is the role whose permissions were snapshotted; nil when no
	// role service was wired or the actor resolves to no role.
	ControlRoleID *uint `gorm:"index" json:"control_role_id"`
	// ControlPermissions is the bitmask of permissions the actor holds in the
	// "enable" state at issuance time (bit order = RustDesk protocol enum).
	// Zero means "nothing explicitly enabled", not "not computed".
	ControlPermissions uint64 `gorm:"not null;default:0" json:"control_permissions"`
	// ControlRoleSnapshotJSON is the full tri-state map at issuance time. It is
	// the only place "disable" survives: the bitmask cannot express it.
	ControlRoleSnapshotJSON string     `gorm:"type:text" json:"control_role_snapshot"`
	ExpiresAt               time.Time  `gorm:"not null;index" json:"expires_at"`
	UsedAt                  *time.Time `json:"used_at"`
	RevokedAt               *time.Time `json:"revoked_at"`
	CreatedAt               time.Time  `json:"created_at"`
}
