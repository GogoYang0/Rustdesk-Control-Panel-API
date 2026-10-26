package model

import "time"

// Strategy is a named set of client configuration options delivered to a
// controlled device through the heartbeat response.
//
// It is configuration, not authorization: Strategy changes what the controlled
// side does (audio on, clipboard off, ...), Control Role describes what an
// operator may do once connected. The two must not be conflated in the UI or
// the docs.
//
// Version increments only when something actually changed; the client echoes it
// back as modified_at, so an unchanged strategy is not re-sent on every
// heartbeat.
type Strategy struct {
	ID             uint   `gorm:"primaryKey" json:"id"`
	OrganizationID uint   `gorm:"uniqueIndex:idx_strategy_org_name,priority:1;not null" json:"organization_id"`
	Name           string `gorm:"size:64;uniqueIndex:idx_strategy_org_name,priority:2;not null" json:"name"`
	// ConfigOptionsJSON is the whitelisted client option map. Only keys from
	// strategy.AllowedOptions may be stored; the client applies them verbatim.
	ConfigOptionsJSON string `gorm:"type:text;not null" json:"config_options"`
	// Version is delivered as the heartbeat response's modified_at.
	Version int64 `gorm:"not null;default:1" json:"version"`
	// Enabled=false keeps the assignment but stops delivery (kill switch).
	Enabled   bool      `gorm:"not null;default:true" json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
