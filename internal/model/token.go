package model

import (
	"encoding/json"
	"time"
)

// APIToken is a personal access token bound to one user and one organization.
//
// Only the SHA-256 digest is stored; the plaintext is shown once at creation.
// TokenPrefix (the first characters) lets a user recognise a token in the list
// without storing anything that could be replayed.
type APIToken struct {
	ID             uint       `gorm:"primaryKey" json:"id"`
	UserID         uint       `gorm:"index;not null" json:"user_id"`
	OrganizationID uint       `gorm:"index;not null" json:"organization_id"`
	Name           string     `gorm:"size:128;not null" json:"name"`
	TokenPrefix    string     `gorm:"size:16;not null" json:"token_prefix"`
	TokenHash      string     `gorm:"size:64;not null;uniqueIndex" json:"-"`
	Permissions    string     `gorm:"type:text;not null" json:"permissions"`
	ExpiresAt      time.Time  `gorm:"not null" json:"expires_at"`
	LastUsedAt     *time.Time `json:"last_used_at"`
	RevokedAt      *time.Time `json:"revoked_at"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// PermissionList decodes the stored permission codes. A malformed value yields
// an empty set so authorization fails closed.
func (t APIToken) PermissionList() []string {
	if t.Permissions == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(t.Permissions), &out); err != nil {
		return nil
	}
	return out
}

// SetPermissions encodes the codes into the stored form.
func (t *APIToken) SetPermissions(codes []string) error {
	if codes == nil {
		codes = []string{}
	}
	raw, err := json.Marshal(codes)
	if err != nil {
		return err
	}
	t.Permissions = string(raw)
	return nil
}

// Active reports whether the token may authenticate at now.
func (t *APIToken) Active(now time.Time) bool {
	return t.RevokedAt == nil && t.ExpiresAt.After(now)
}
