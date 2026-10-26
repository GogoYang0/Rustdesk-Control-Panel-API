package model

import "time"

// Device is a RustDesk endpoint registered inside one organization.
//
// The contract identifies devices by rustdesk_id, so that pair is the natural
// key per organization: re-registering the same id updates the existing row
// instead of creating a duplicate.
type Device struct {
	ID             uint `gorm:"primaryKey" json:"id"`
	OrganizationID uint `gorm:"uniqueIndex:idx_device_org_rustdesk;not null" json:"organization_id"`
	// The plain index backs the credential-free audit ingest, which looks a
	// device up by rustdesk id alone (the id is unique per organization, not
	// globally) before it knows the tenant.
	RustdeskID string `gorm:"uniqueIndex:idx_device_org_rustdesk;index;size:64;not null" json:"rustdesk_id"`
	// StrategyID is the device-level assignment; nil falls back to the device
	// group and then to the owner's membership (design D1).
	StrategyID *uint  `gorm:"index" json:"strategy_id"`
	Name       string `gorm:"size:128;not null" json:"name"`
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
	BoundUUID string `gorm:"size:255" json:"-"`
	// BindingGeneration increments every time the binding changes (first
	// claim, administrator re-bind). Compat sessions snapshot the generation
	// they were issued under and their credential-free activity is dropped
	// once the device's generation has moved past it, so a session issued
	// under an earlier binding can never drive the device again.
	BindingGeneration uint64     `gorm:"not null;default:0" json:"-"`
	LastSeenAt        *time.Time `json:"last_seen_at"`
	// Disabled stops the device: its compat sessions are revoked on the
	// transition, new client claims and compat logins are refused, heartbeats
	// are dropped and ticket redemption is a conflict. History stays.
	Disabled   bool       `gorm:"not null;default:false" json:"disabled"`
	DisabledAt *time.Time `json:"disabled_at,omitempty"`
	DisabledBy uint       `gorm:"not null;default:0" json:"disabled_by,omitempty"`
	// DeviceGroupID is the single device group this device belongs to. A device
	// is in at most one group; moving it rewrites this column inside the same
	// transaction, and deleting its group clears it.
	DeviceGroupID *uint `gorm:"index" json:"device_group_id"`
	// OwnerUserID is the organization member this device belongs to, nil when
	// nobody claimed it. Ownership is what makes "user group -> user group"
	// rules expressible: the target side expands to the devices owned by the
	// members of that group. Deactivated members keep their ownership rows (the
	// history stays attributable) but stop being reachable through rules.
	OwnerUserID *uint `gorm:"index" json:"owner_user_id"`
	// Note is a free-form operator annotation, written through the management
	// API or the client --assign path.
	Note      string    `gorm:"size:255;not null;default:''" json:"note"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
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
	// ConnIDs is the JSON array of connection ids the client reported on this
	// heartbeat. Only these ids may be sent back in a disconnect field.
	ConnIDs string `gorm:"type:text" json:"conn_ids"`
}
