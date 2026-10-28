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
	OrganizationID uint   `gorm:"uniqueIndex:idx_strategy_org_name,priority:1;uniqueIndex:idx_strategy_org_namekey,priority:1;not null" json:"organization_id"`
	Name           string `gorm:"size:64;uniqueIndex:idx_strategy_org_name,priority:2;not null" json:"name"`
	// NameKey is the lower-cased name. Uniqueness is case-insensitive (the CLI
	// resolves names that way), and SQLite's LOWER() only folds ASCII, so the
	// folded form is stored and indexed instead of being computed in SQL.
	NameKey string `gorm:"size:64;uniqueIndex:idx_strategy_org_namekey,priority:2;not null" json:"name_key"`
	// ConfigOptionsJSON is the whitelisted client option map. Only keys from
	// strategy.AllowedOptions may be stored; the client applies them verbatim.
	ConfigOptionsJSON string `gorm:"type:text;not null" json:"config_options"`
	// Version is delivered as the heartbeat response's modified_at.
	//
	// It is allocated from the organization's sequence, not from this row: the
	// client stores one number and cannot tell which strategy it came from, so
	// two strategies sharing a version would make "switch to the other one"
	// look like "already up to date" and deliver nothing.
	Version int64 `gorm:"not null" json:"version"`
	// ClearedKeysJSON lists option keys the operator removed from
	// ConfigOptionsJSON. The client applies only the keys it receives, so a
	// removed key must still be sent once as an empty value to be reset;
	// keeping the set on the row means every delivery carries the reset.
	ClearedKeysJSON string `gorm:"type:text;not null" json:"cleared_keys"`
	// Enabled=false keeps the assignment but stops delivery (kill switch).
	//
	// No `default:true` tag on purpose: GORM omits a zero-value field that has
	// a default, so inserting a strategy with Enabled=false would silently
	// store true — the kill switch would not stick. Every writer sets the
	// field explicitly instead.
	Enabled   bool      `gorm:"not null" json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
