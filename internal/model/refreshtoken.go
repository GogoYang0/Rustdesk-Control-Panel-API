package model

import "time"

// RefreshToken stores the hash of an opaque refresh token.
// The plain token never touches the database, only its SHA-256 hash.
type RefreshToken struct {
	ID         uint       `gorm:"primaryKey" json:"id"`
	UserID     uint       `gorm:"index;not null" json:"user_id"`
	TokenHash  string     `gorm:"size:64;uniqueIndex;not null" json:"-"`
	ExpiresAt  time.Time  `gorm:"not null" json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
	ReplacedBy *uint      `json:"replaced_by"`
	CreatedAt  time.Time  `json:"created_at"`
}
