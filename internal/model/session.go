package model

import "time"

// Session origins (contract v0.4.0 SessionOrigin).
const (
	SessionOriginPanel  = "panel"
	SessionOriginNative = "native"
)

// Session statuses.
const (
	SessionStatusOpen   = "open"
	SessionStatusClosed = "closed"
	SessionStatusDenied = "denied"
)

// Session end reasons.
const (
	// SessionEndDisconnected means a connection-end event was recognised in
	// the hbbs/hbbr log.
	SessionEndDisconnected = "disconnected"
	// SessionEndIdleTimeout means no related event arrived inside the idle
	// window; the sweeper closed the session.
	SessionEndIdleTimeout = "idle_timeout"
	// SessionEndPolicyExceeded means the session ran past max_session_minutes.
	// The real connection is not cut: the panel is not in the signalling path.
	SessionEndPolicyExceeded = "policy_exceeded"
	// SessionEndPolicyDenied marks the recording row for a denied issuance.
	SessionEndPolicyDenied = "policy_denied"
	// SessionEndAdminEnded marks an operator ending the session record. The
	// panel is not in the signalling path, so the transport drops when the
	// client consumes the queued disconnect on its next heartbeat.
	SessionEndAdminEnded = "admin_ended"
)

// Session is one remote-control session.
//
// panel sessions are created when a ticket is redeemed; native sessions are
// inferred from hbbs/hbbr log events. Only open panel sessions count against a
// concurrency policy (native is record-only, design D10).
type Session struct {
	ID             uint   `gorm:"primaryKey" json:"id"`
	OrganizationID uint   `gorm:"index:idx_session_org_status,priority:1;index:idx_session_org_started,priority:1;not null" json:"organization_id"`
	DeviceID       uint   `gorm:"index:idx_session_device;not null" json:"device_id"`
	RustdeskID     string `gorm:"size:64" json:"rustdesk_id"`
	ActorUserID    *uint  `gorm:"index" json:"actor_user_id"`
	Origin         string `gorm:"size:16;not null" json:"origin"`
	Status         string `gorm:"size:16;not null;index:idx_session_org_status,priority:2" json:"status"`
	TicketID       *uint  `gorm:"index" json:"ticket_id"`
	PolicyID       *uint  `gorm:"index" json:"policy_id"`
	// ControlPermissions is copied from the ticket at redemption: the session
	// records what the operator was allowed to do when it started, even if the
	// role is edited afterwards.
	ControlPermissions uint64     `gorm:"not null;default:0" json:"control_permissions"`
	StartedAt          time.Time  `gorm:"not null;index:idx_session_org_started,priority:2" json:"started_at"`
	EndedAt            *time.Time `json:"ended_at"`
	LastActivityAt     *time.Time `gorm:"index" json:"last_activity_at"`
	EndReason          *string    `gorm:"size:64" json:"end_reason"`
	// Revision increments on every state change. Optimistic concurrency must be
	// spelled `WHERE id = ? AND revision = ?` plus `SET revision = revision + 1`;
	// writing a loaded absolute value back (Save, Select("*")) silently defeats
	// it, so state transitions belong in an explicit update, not in a save.
	Revision  uint64    `gorm:"not null;default:0" json:"revision"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SessionEvent is one entry in a session's timeline (started, connected,
// approved, disconnected, closed, ...). The timeline is audit evidence, so
// events are append-only.
type SessionEvent struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	OrganizationID uint      `gorm:"index:idx_session_event_session,priority:1;not null" json:"organization_id"`
	SessionID      uint      `gorm:"not null;index:idx_session_event_session,priority:2" json:"session_id"`
	Kind           string    `gorm:"size:64;not null" json:"kind"`
	At             time.Time `gorm:"not null;index:idx_session_event_session,priority:3" json:"at"`
	// DetailJSON is a JSON object with event-specific context (peer address,
	// log line, decider, ...). Stored as text so SQLite and MySQL behave the
	// same way; the JSON suffix marks it as "marshal before use".
	DetailJSON string    `gorm:"type:text" json:"detail"`
	CreatedAt  time.Time `json:"created_at"`
}
