package model

import "time"

// Ticket is a one-shot connection ticket.
//
// Plaintext never touches the database: only TokenHash is stored, and the
// plaintext is returned exactly once in the issuance response. used_at is the
// one-shot marker, revoked_at is set by offboarding.
type Ticket struct {
	ID             uint  `gorm:"primaryKey" json:"id"`
	OrganizationID uint  `gorm:"index;not null;index:idx_ticket_org_device,priority:1" json:"organization_id"`
	DeviceID       uint  `gorm:"not null;index:idx_ticket_org_device,priority:2" json:"device_id"`
	ActorUserID    uint  `gorm:"index;not null" json:"actor_user_id"`
	ApprovalID     *uint `gorm:"index" json:"approval_id"`
	// TokenHash is the digest of the plaintext token; unique so a collision or
	// replay can never resolve to two tickets.
	TokenHash string `gorm:"size:64;not null;uniqueIndex" json:"-"`
	// PolicySnapshot is the effective policy at issuance time (JSON), kept for
	// audit and troubleshooting after policies change or disappear.
	PolicySnapshot string     `gorm:"type:text" json:"policy_snapshot"`
	ExpiresAt      time.Time  `gorm:"not null;index" json:"expires_at"`
	UsedAt         *time.Time `json:"used_at"`
	RevokedAt      *time.Time `json:"revoked_at"`
	CreatedAt      time.Time  `json:"created_at"`
}
