package model

import "time"

// CompatLoginChallenge is the short-lived second factor proof handed to the
// RustDesk client during a compat login.
//
// The client treats the value as opaque: it sends it back as "secret" together
// with the 6-digit code, and never derives anything from it. Only the SHA-256
// digest is stored, so a database leak does not hand out login capability.
// The challenge is bound to the device identity that requested it: moving it to
// another machine must fail.
type CompatLoginChallenge struct {
	ID             uint      `gorm:"primaryKey"`
	UserID         uint      `gorm:"index;not null"`
	OrganizationID uint      `gorm:"index;not null"`
	DeviceID       string    `gorm:"size:64;not null"`
	UUID           string    `gorm:"size:128;not null"`
	SecretHash     string    `gorm:"size:64;uniqueIndex;not null"`
	ExpiresAt      time.Time `gorm:"index;not null"`
	UsedAt         *time.Time
	Attempts       int       `gorm:"not null;default:0"`
	CreatedAt      time.Time `gorm:"not null"`
}
