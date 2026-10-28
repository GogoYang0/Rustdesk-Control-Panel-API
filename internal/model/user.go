// Package model holds the GORM data models.
package model

import (
	"strings"
	"time"

	"gorm.io/gorm"
)

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

// BeforeSave normalizes the mailbox on every write path (invite accept, admin
// create, self-service email change). Every lookup in the codebase matches
// case-insensitively (LOWER(email)), so storing mixed-case would create shadow
// accounts that some queries see and others do not — and two accounts whose
// emails differ only by case are the CWE-178 confusion an external login must
// never be allowed to guess across.
func (u *User) BeforeSave(tx *gorm.DB) error {
	u.Email = NormalizeEmail(u.Email)
	return nil
}

// NormalizeEmail canonicalizes a mailbox for both storage and lookup: query
// sites MUST pass their input through this helper so the key matches what
// BeforeSave stored.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
