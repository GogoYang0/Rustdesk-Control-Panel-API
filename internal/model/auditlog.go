package model

import "time"

// AuditLog records one action inside an organization.
//
// Seq is assigned per organization and must be continuous: (OrganizationID, Seq)
// is unique, and the auditor retries on collisions so no gaps appear.
type AuditLog struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	OrganizationID uint      `gorm:"uniqueIndex:idx_audit_org_seq;not null" json:"organization_id"`
	Seq            uint64    `gorm:"uniqueIndex:idx_audit_org_seq;not null" json:"seq"`
	ActorUserID    uint      `gorm:"index" json:"actor_user_id"`
	Action         string    `gorm:"size:128;not null" json:"action"`
	TargetType     string    `gorm:"size:64" json:"target_type"`
	TargetID       string    `gorm:"size:64" json:"target_id"`
	Detail         string    `gorm:"type:text" json:"detail"`
	CreatedAt      time.Time `json:"created_at"`
}
