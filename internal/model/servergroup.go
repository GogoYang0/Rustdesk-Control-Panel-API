package model

import "time"

// ServerGroup states.
const (
	ServerGroupProvisioning = "provisioning"
	ServerGroupDeployed     = "deployed"
	ServerGroupFailed       = "failed"
)

// ServerGroup holds the per-organization hbbs/hbbr allocation.
//
// Each organization owns a contiguous block of five host ports, because one host
// port can be published only once per protocol:
//
//	HbbsPort+0 -> hbbs 21115 (tcp, NAT type test)
//	HbbsPort+1 -> hbbs 21116 (tcp and udp, id registry and heartbeat)
//	HbbsPort+2 -> hbbs 21118 (tcp, web client websocket)
//	HbbrPort+0 -> hbbr 21117 (tcp, relay)
//	HbbrPort+1 -> hbbr 21119 (tcp, web client relay websocket)
//
// HbbrPort is therefore always HbbsPort+3.
//
// The unique indexes on ports and organization are the source of truth for the
// port pool: allocation is an insert that either wins or collides, which keeps
// concurrent provisioning safe without a separate lock.
type ServerGroup struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	OrganizationID uint      `gorm:"uniqueIndex;not null" json:"organization_id"`
	HbbsPort       uint16    `gorm:"uniqueIndex;not null" json:"hbbs_port"`
	HbbrPort       uint16    `gorm:"uniqueIndex;not null" json:"hbbr_port"`
	PubKey         string    `gorm:"size:128" json:"pub_key"`
	Fingerprint    string    `gorm:"size:128" json:"fingerprint"`
	ConfigSnapshot string    `gorm:"type:text" json:"config_snapshot"`
	State          string    `gorm:"size:32;not null" json:"state"`
	LastError      string    `gorm:"type:text" json:"last_error"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// TableName keeps the port uniqueness indexes stable.
func (ServerGroup) TableName() string { return "server_groups" }
