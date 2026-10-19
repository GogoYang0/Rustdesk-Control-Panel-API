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
