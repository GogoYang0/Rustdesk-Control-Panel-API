package model

import "time"

// Approval kinds.
const (
	// ApprovalKindPre approves one upcoming ticket issuance.
	ApprovalKindPre = "pre_approval"
	// ApprovalKindRatification acknowledges a native session that already
	// violated policy. It never yields a ticket.
	ApprovalKindRatification = "ratification"
)

// Approval statuses.
const (
	ApprovalStatusPending  = "pending"
	ApprovalStatusApproved = "approved"
	ApprovalStatusDenied   = "denied"
	ApprovalStatusExpired  = "expired"
)

// Approval is a request for a human decision: either "may this member connect
// to this device" (pre-approval) or "this native session already happened,
// acknowledge it" (ratification).
type Approval struct {
	ID             uint       `gorm:"primaryKey" json:"id"`
	OrganizationID uint       `gorm:"not null;index:idx_approval_org_status,priority:1" json:"organization_id"`
	DeviceID       uint       `gorm:"not null;index" json:"device_id"`
	Kind           string     `gorm:"size:16;not null" json:"kind"`
	SessionID      *uint      `gorm:"index" json:"session_id"`
	ActorUserID    uint       `gorm:"index;not null" json:"actor_user_id"`
	Status         string     `gorm:"size:16;not null;index:idx_approval_org_status,priority:2" json:"status"`
	RequestedAt    time.Time  `gorm:"not null" json:"requested_at"`
	ExpiresAt      time.Time  `gorm:"not null;index" json:"expires_at"`
	DecidedBy      *uint      `json:"decided_by"`
	DecidedAt      *time.Time `json:"decided_at"`
	Reason         *string    `gorm:"size:500" json:"reason"`
	// TicketID is set when an approval is consumed by an issuance. It stays
	// nil for ratification, which never produces a ticket.
	TicketID  *uint     `gorm:"index" json:"ticket_id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
