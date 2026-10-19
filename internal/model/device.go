package model

import "time"

// Device is a RustDesk endpoint registered inside one organization.
//
// The contract identifies devices by rustdesk_id, so that pair is the natural
// key per organization: re-registering the same id updates the existing row
// instead of creating a duplicate.
type Device struct {
	ID             uint       `gorm:"primaryKey" json:"id"`
	OrganizationID uint       `gorm:"uniqueIndex:idx_device_org_rustdesk;not null" json:"organization_id"`
	RustdeskID     string     `gorm:"uniqueIndex:idx_device_org_rustdesk;size:64;not null" json:"rustdesk_id"`
	Name           string     `gorm:"size:128;not null" json:"name"`
	LastSeenAt     *time.Time `json:"last_seen_at"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// OnlineWindow is how fresh a heartbeat must be for the device to count as
// online.
const OnlineWindow = 90 * time.Second

// Online reports whether the device sent a heartbeat within OnlineWindow.
func (d *Device) Online(now time.Time) bool {
	if d.LastSeenAt == nil {
		return false
	}
	return now.Sub(*d.LastSeenAt) < OnlineWindow
}

// DeviceHeartbeat records one heartbeat event.
type DeviceHeartbeat struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	OrganizationID uint      `gorm:"index;not null" json:"organization_id"`
	DeviceID       uint      `gorm:"index;not null" json:"device_id"`
	At             time.Time `gorm:"not null" json:"at"`
	Source         string    `gorm:"size:32" json:"source"`
}
