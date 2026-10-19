package model

import "time"

// Purpose values for VerificationToken.
const (
	// VerificationPurposeEmail proves control of the account mailbox before
	// login is allowed.
	VerificationPurposeEmail = "email_verify"
)

// VerificationToken is a single-use, time-limited token that proves control
// of a mailbox. Only the SHA-256 hash of the token is stored; the plaintext
// token exists solely inside the verification email.
type VerificationToken struct {
	ID        uint      `gorm:"primaryKey"`
	UserID    uint      `gorm:"not null;index"`
	TokenHash string    `gorm:"size:64;uniqueIndex;not null"`
	Purpose   string    `gorm:"size:32;not null;default:email_verify;index"`
	ExpiresAt time.Time `gorm:"not null"`
	UsedAt    *time.Time
	CreatedAt time.Time
}
