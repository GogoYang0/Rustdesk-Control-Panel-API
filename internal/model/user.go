// Package model holds the GORM data models.
package model

import "time"

// User is a globally unique account; organization membership links users to orgs.
type User struct {
	ID           uint   `gorm:"primaryKey" json:"id"`
	Email        string `gorm:"size:255;uniqueIndex;not null" json:"email"`
	PasswordHash string `gorm:"size:255;not null" json:"-"`
	// EmailVerified gates every login path: false until the mailbox is
	// proven with a verification token. NOT NULL + DEFAULT false keeps the
	// column safe for ALTER-based migration: pre-existing rows are backfilled
	// to true once at startup (see cmd/server/main.go), and no NULL can ever
	// reach a Go bool scan.
	EmailVerified bool      `gorm:"not null;default:false" json:"-"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}
