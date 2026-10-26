package model

import "time"

// Disconnect request states. A request is pending until a heartbeat that
// reports live connections consumes it; otherwise it expires so a stale
// request cannot kill an unrelated connection days later.
const (
	DisconnectStatusPending   = "pending"
	DisconnectStatusFulfilled = "fulfilled"
	DisconnectStatusExpired   = "expired"
)

// DeviceDisconnect is one "cut the current sessions of this device" request.
//
// The panel cannot tear down a connection itself (it is not in the signalling
// path); the client does it when the next heartbeat response carries
// `disconnect`. The request therefore records intent and outcome, not a live
// action.
type DeviceDisconnect struct {
	ID             uint       `gorm:"primaryKey" json:"id"`
	OrganizationID uint       `gorm:"index:idx_disconnect_org_status,priority:1;not null" json:"organization_id"`
	DeviceID       uint       `gorm:"index:idx_disconnect_device;not null" json:"device_id"`
	Reason         string     `gorm:"size:255;not null" json:"reason"`
	RequestedBy    uint       `gorm:"not null" json:"requested_by"`
	Status         string     `gorm:"size:16;index:idx_disconnect_org_status,priority:2;not null" json:"status"`
	RequestedAt    time.Time  `gorm:"not null" json:"requested_at"`
	FulfilledAt    *time.Time `json:"fulfilled_at"`
	ExpiresAt      time.Time  `gorm:"index;not null" json:"expires_at"`
	// ConnCount is how many connection ids the consuming heartbeat reported.
	ConnCount int `gorm:"not null;default:0" json:"conn_count"`
}
