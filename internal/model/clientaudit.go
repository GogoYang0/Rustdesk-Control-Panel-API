package model

import "time"

// Connection log row states. A "new" audit report opens a row and the matching
// "close" report closes it; an orphan close creates an already-closed row so
// the evidence is never dropped.
const (
	ConnectionLogStatusOpen   = "open"
	ConnectionLogStatusClosed = "closed"
)

// ConnectionLog is one connection reported by the controlled client
// (POST /api/audit/conn). The client owns the identity: (rustdesk_id, conn_id,
// session_id) is unique because the same connection may be retried with a new
// nonce but must stay one row.
type ConnectionLog struct {
	ID             uint       `gorm:"primaryKey" json:"id"`
	OrganizationID uint       `gorm:"uniqueIndex:idx_connection_log_identity,priority:1;index:idx_connection_log_org_started,priority:1;not null" json:"organization_id"`
	DeviceID       uint       `gorm:"index" json:"device_id"`
	RustdeskID     string     `gorm:"size:64;uniqueIndex:idx_connection_log_identity,priority:2;not null" json:"rustdesk_id"`
	ConnID         int64      `gorm:"uniqueIndex:idx_connection_log_identity,priority:3;not null" json:"conn_id"`
	SessionID      int64      `gorm:"uniqueIndex:idx_connection_log_identity,priority:4;not null" json:"session_id"`
	IP             string     `gorm:"size:64" json:"ip"`
	Status         string     `gorm:"size:16;not null;index" json:"status"`
	StartedAt      time.Time  `gorm:"not null;index:idx_connection_log_org_started,priority:2" json:"started_at"`
	EndedAt        *time.Time `json:"ended_at"`
	Note           string     `gorm:"size:512" json:"note"`
	ConnAuditRef   string     `gorm:"size:128" json:"conn_audit_ref"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// FileLog is one file-transfer report from the controlled client
// (POST /api/audit/file). Direction is "send" (client sent files to the
// controller) or "receive"; InfoJSON keeps the client's info blob verbatim.
type FileLog struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	OrganizationID uint      `gorm:"index:idx_file_log_org_created,priority:1;not null" json:"organization_id"`
	DeviceID       uint      `gorm:"index" json:"device_id"`
	RustdeskID     string    `gorm:"size:64;not null;index" json:"rustdesk_id"`
	PeerID         string    `gorm:"size:64" json:"peer_id"`
	ConnID         int64     `json:"conn_id"`
	Direction      string    `gorm:"size:16;not null" json:"direction"`
	Path           string    `gorm:"type:text" json:"path"`
	IsFile         bool      `gorm:"not null;default:false" json:"is_file"`
	FileCount      int       `gorm:"not null;default:0" json:"file_count"`
	FilesJSON      string    `gorm:"type:text" json:"files"`
	InfoJSON       string    `gorm:"type:text" json:"info"`
	IP             string    `gorm:"size:64" json:"ip"`
	Name           string    `gorm:"size:128" json:"name"`
	CreatedAt      time.Time `gorm:"index:idx_file_log_org_created,priority:2" json:"created_at"`
}

// AuditNonce deduplicates client audit retries. The client retries transport
// errors and 5xx for up to 120 seconds and the upstream API server only
// remembers a nonce for five minutes, so rows older than the sweep window are
// deleted by a worker.
type AuditNonce struct {
	ID             uint      `gorm:"primaryKey"`
	OrganizationID uint      `gorm:"index;not null"`
	Nonce          string    `gorm:"size:64;uniqueIndex;not null"`
	CreatedAt      time.Time `gorm:"index;not null"`
}
