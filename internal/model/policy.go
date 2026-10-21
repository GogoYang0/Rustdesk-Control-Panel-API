package model

import "time"

// Policy is a connection policy. Every enabled policy applies at once and each
// dimension takes the strictest bound, so a ticket needs no policy selector.
type Policy struct {
	ID             uint   `gorm:"primaryKey" json:"id"`
	OrganizationID uint   `gorm:"index;not null;uniqueIndex:idx_policy_org_name,priority:1" json:"organization_id"`
	Name           string `gorm:"size:128;not null;uniqueIndex:idx_policy_org_name,priority:2" json:"name"`
	Enabled        bool   `gorm:"not null" json:"enabled"`
	// Nil means "no limit" for every numeric bound below.
	MaxConcurrentSessions *int64 `json:"max_concurrent_sessions"`
	MaxSessionMinutes     *int64 `json:"max_session_minutes"`
	// Allowed window in UTC minutes-of-day; start > end is an overnight
	// window, both nil means all day, start == end is invalid.
	AllowedStartMinute *int64    `json:"allowed_start_minute"`
	AllowedEndMinute   *int64    `json:"allowed_end_minute"`
	RequireApproval    bool      `gorm:"not null" json:"require_approval"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// MinInt64 returns the smaller of two optional bounds, treating nil as
// "unbounded" so the caller can fold a set of policies into one effective limit.
func MinInt64(a, b *int64) *int64 {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	if *b < *a {
		return b
	}
	return a
}
