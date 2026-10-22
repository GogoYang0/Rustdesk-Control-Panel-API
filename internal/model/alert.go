package model

import "time"

// Alert severities.
const (
	AlertSeverityInfo     = "info"
	AlertSeverityWarning  = "warning"
	AlertSeverityCritical = "critical"
)

// Alert kinds. Pre-approval blocks are not alerts: they are the normal
// controlled path and would drown the list.
const (
	AlertKindConcurrencyExceeded = "concurrency_exceeded"
	AlertKindDurationExceeded    = "duration_exceeded"
	AlertKindOutsideWindow       = "outside_window"
)

// Alert is a policy violation record. Native violations are recorded here
// without blocking anything (design D10).
type Alert struct {
	ID             uint   `gorm:"primaryKey" json:"id"`
	OrganizationID uint   `gorm:"not null;index:idx_alert_org_created,priority:1" json:"organization_id"`
	SessionID      *uint  `gorm:"index" json:"session_id"`
	DeviceID       *uint  `gorm:"index" json:"device_id"`
	Kind           string `gorm:"size:64;not null" json:"kind"`
	Severity       string `gorm:"size:16;not null" json:"severity"`
	// DetailJSON carries the violation context (limit, observed value, window).
	DetailJSON string    `gorm:"type:text" json:"detail"`
	CreatedAt  time.Time `gorm:"not null;index:idx_alert_org_created,priority:2" json:"created_at"`
}
