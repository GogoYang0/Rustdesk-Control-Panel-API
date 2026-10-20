package model

import "time"

// Device is a RustDesk endpoint registered inside one organization.
//
// The contract identifies devices by rustdesk_id, so that pair is the natural
// key per organization: re-registering the same id updates the existing row
// instead of creating a duplicate.
type Device struct {
	ID             uint   `gorm:"primaryKey" json:"id"`
	OrganizationID uint   `gorm:"uniqueIndex:idx_device_org_rustdesk;not null" json:"organization_id"`
	RustdeskID     string `gorm:"uniqueIndex:idx_device_org_rustdesk;size:64;not null" json:"rustdesk_id"`
	Name           string `gorm:"size:128;not null" json:"name"`
	// BoundUUID records the client instance uuid that first presented this
	// rustdesk id (empty until a compat login claims it). The client
	// protocol carries no ownership secret, so this hardware-stable uuid is
	// the ownership anchor: a login presenting a different uuid is refused
	// instead of taking the binding over (CWE-863).
	//
	// The column stays at 255 while CompatSession.UUID is 128: the login path
	// rejects anything longer than 128 before writing here, so the wider column
	// only avoids a schema shrink that could fail on rows written by an earlier
	// build.
	BoundUUID  string     `gorm:"size:255" json:"-"`
	LastSeenAt *time.Time `json:"last_seen_at"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// OnlineWindow is how fresh a heartbeat must be for the device to count as
// online.
const OnlineWindow = 90 * time.Second

// ClockSkew tolerates small clock differences between nodes.
const ClockSkew = 5 * time.Second

// Online reports whether the device sent a heartbeat within OnlineWindow.
//
// A timestamp further in the future than ClockSkew is treated as offline: a
// skewed node must not keep a device online until the future time plus the
// window has elapsed.
func (d *Device) Online(now time.Time) bool {
	if d.LastSeenAt == nil {
		return false
	}
	age := now.Sub(*d.LastSeenAt)
	if age < -ClockSkew {
		return false
	}
	return age < OnlineWindow
}

// DeviceHeartbeat records one heartbeat event.
type DeviceHeartbeat struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	OrganizationID uint      `gorm:"index;not null" json:"organization_id"`
	DeviceID       uint      `gorm:"index;not null" json:"device_id"`
	At             time.Time `gorm:"not null" json:"at"`
	Source         string    `gorm:"size:32" json:"source"`
}
