package model

import "time"

// Log sources, levels and kinds mirror the LogEvent contract (task 2).
const (
	LogSourceHbbs = "hbbs"
	LogSourceHbbr = "hbbr"

	LogLevelInfo  = "info"
	LogLevelWarn  = "warn"
	LogLevelError = "error"

	LogKindConn  = "conn"
	LogKindFile  = "file"
	LogKindError = "error"
	LogKindOther = "other"
)

// LogEvent is one parsed line collected from an organization's hbbs/hbbr
// containers. Rows are tenant-scoped: the plugin fails closed without an
// organization context.
type LogEvent struct {
	ID             uint   `gorm:"primaryKey" json:"id"`
	OrganizationID uint   `gorm:"index:idx_log_org_time,priority:1;not null" json:"organization_id"`
	DeviceID       *uint  `gorm:"index" json:"device_id"`
	Source         string `gorm:"size:8;not null" json:"source"`
	Level          string `gorm:"size:8;not null" json:"level"`
	Kind           string `gorm:"size:16;not null" json:"kind"`
	// DetailJSON holds the named capture groups of the matching rule plus
	// the raw line; it is always a JSON object.
	DetailJSON string    `gorm:"type:text" json:"detail_json"`
	OccurredAt time.Time `gorm:"index:idx_log_org_time,priority:2;not null" json:"occurred_at"`
	CreatedAt  time.Time `json:"created_at"`
}

// DefaultLogEventRetentionDays is how long collected events are kept before
// the maintenance sweep drops them (M2 keeps pruning out of scope; the
// constant documents the intended policy for M3).
const DefaultLogEventRetentionDays = 30
