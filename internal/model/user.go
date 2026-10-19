// Package model holds the GORM data models.
package model

import "time"

// User is a globally unique account; organization membership links users to orgs.
type User struct {
	ID           uint   `gorm:"primaryKey" json:"id"`
	Email        string `gorm:"size:255;uniqueIndex;not null" json:"email"`
	PasswordHash string `gorm:"size:255;not null" json:"-"`
	// EmailVerified gates every login path: false until the mailbox is
	// proven with a verification token. Rows created before the field
	// existed are backfilled to true once at startup (cmd/server/main.go).
	EmailVerified bool      `json:"-"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}
