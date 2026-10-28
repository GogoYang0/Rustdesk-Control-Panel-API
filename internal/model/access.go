package model

import "time"

// User group kinds. Every organization owns exactly one reserved everyone
// group whose membership is implicit (membership rows are never written for
// it); custom groups hold an explicit member set.
const (
	UserGroupKindEveryone = "everyone"
	UserGroupKindCustom   = "custom"
	// EveryoneGroupName is the display name reserved for the implicit group.
	EveryoneGroupName = "everyone"
)

// Access rule target kinds: one concrete device group, every device of the
// organization, or one user group (expanded to the devices its members own).
const (
	AccessTargetKindDeviceGroup = "device_group"
	AccessTargetKindAllDevices  = "all_devices"
	AccessTargetKindUserGroup   = "user_group"
)

// UserGroup is an organization-scoped set of users used as the source side of
// access rules.
type UserGroup struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	OrganizationID uint      `gorm:"not null;uniqueIndex:idx_user_group_org_name,priority:1" json:"organization_id"`
	Name           string    `gorm:"size:64;not null;uniqueIndex:idx_user_group_org_name,priority:2" json:"name"`
	Kind           string    `gorm:"size:16;not null" json:"kind"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// UserGroupMember is one explicit membership of a custom group. A user may
// belong to any number of groups.
type UserGroupMember struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	OrganizationID uint      `gorm:"not null;uniqueIndex:idx_user_group_member_unique,priority:1;index:idx_user_group_member_group,priority:1" json:"organization_id"`
	GroupID        uint      `gorm:"not null;uniqueIndex:idx_user_group_member_unique,priority:2;index:idx_user_group_member_group,priority:2" json:"group_id"`
	UserID         uint      `gorm:"not null;uniqueIndex:idx_user_group_member_unique,priority:3" json:"user_id"`
	CreatedAt      time.Time `json:"created_at"`
}

// DeviceGroup is an organization-scoped set of devices. A device belongs to at
// most one device group; Device.DeviceGroupID carries the membership.
type DeviceGroup struct {
	ID             uint   `gorm:"primaryKey" json:"id"`
	OrganizationID uint   `gorm:"not null;uniqueIndex:idx_device_group_org_name,priority:1" json:"organization_id"`
	Name           string `gorm:"size:64;not null;uniqueIndex:idx_device_group_org_name,priority:2" json:"name"`
	// StrategyID applies to every device in the group unless the device itself
	// carries one (design D1).
	StrategyID *uint     `gorm:"index" json:"strategy_id"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// AccessRule grants a user group access to a device group, to a user group's
// owned devices, or to every device. Only allow rules exist; several rules
// compose as a union.
//
// TargetGroupID is NOT NULL with a 0 sentinel because MySQL unique indexes do
// not treat multiple NULLs as distinct: all_devices rules store 0 there and the
// contract maps it to null. For the other kinds it holds the device group id or
// the user group id, selected by TargetKind.
type AccessRule struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	OrganizationID uint      `gorm:"not null;uniqueIndex:idx_access_rule_unique,priority:1" json:"organization_id"`
	SourceGroupID  uint      `gorm:"not null;uniqueIndex:idx_access_rule_unique,priority:2;index" json:"source_group_id"`
	TargetKind     string    `gorm:"size:16;not null;uniqueIndex:idx_access_rule_unique,priority:3" json:"target_kind"`
	TargetGroupID  uint      `gorm:"not null;default:0;uniqueIndex:idx_access_rule_unique,priority:4" json:"target_group_id"`
	CreatedAt      time.Time `json:"created_at"`
}
