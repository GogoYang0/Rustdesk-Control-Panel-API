package model

import (
	"errors"
	"fmt"
	"time"
)

// Invitation errors.
var (
	ErrInvitationExpired = errors.New("invitation expired")
	ErrInvitationUsed    = errors.New("invitation already accepted")
)

// Invitation grants a role in an organization to an email address.
// Only the SHA-256 hash of the invitation token is stored.
type Invitation struct {
	ID             uint       `gorm:"primaryKey" json:"id"`
	OrganizationID uint       `gorm:"index;not null" json:"organization_id"`
	Email          string     `gorm:"size:255;index;not null" json:"email"`
	Role           string     `gorm:"size:16;not null" json:"role"`
	TokenHash      string     `gorm:"size:64;uniqueIndex;not null" json:"-"`
	ExpiresAt      time.Time  `gorm:"not null" json:"expires_at"`
	AcceptedBy     *uint      `json:"accepted_by"`
	AcceptedAt     *time.Time `json:"accepted_at"`
	CreatedAt      time.Time  `json:"created_at"`
}

// Acceptable reports whether the invitation can still be accepted at now.
func (i *Invitation) Acceptable(now time.Time) error {
	if i.AcceptedAt != nil {
		return fmt.Errorf("%w", ErrInvitationUsed)
	}
	if !now.Before(i.ExpiresAt) {
		return fmt.Errorf("%w", ErrInvitationExpired)
	}
	return nil
}
