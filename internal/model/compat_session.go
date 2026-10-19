package model

import "time"

// CompatSession binds one RustDesk client login to exactly one organization
// (issue C16): the client cannot pass an organization selector, so the
// session fixes the tenant for /api/peers, heartbeat and sysinfo. The JWT
// jti matches the session row; logout revokes by jti.
type CompatSession struct {
	ID             uint      `gorm:"primaryKey"`
	OrganizationID uint      `gorm:"index;not null"`
	UserID         uint      `gorm:"index;not null"`
	JTI            string    `gorm:"size:64;uniqueIndex;not null"`
	DeviceID       string    `gorm:"size:64"`
	UUID           string    `gorm:"size:128;index"`
	ExpiresAt      time.Time `gorm:"not null"`
	RevokedAt      *time.Time
	CreatedAt      time.Time
}

// Active reports whether the session may still be used.
func (s *CompatSession) Active(now time.Time) bool {
	return s.RevokedAt == nil && now.Before(s.ExpiresAt)
}
