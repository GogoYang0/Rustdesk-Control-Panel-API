// Package authz holds the role-to-permission matrix and its gin middleware.
package authz

import "fmt"

// Permission identifiers used across handlers.
const (
	PermOrgAdmin     = "org.admin"
	PermMemberManage = "member.manage"
	PermDeviceRead   = "device.read"
	PermDeviceWrite  = "device.write"
	PermAuditRead    = "audit.read"
	PermAddressBook  = "addressbook.write"
	// PermPolicyWrite gates connection policies. The contract grants it to
	// owner and admin, so it is a distinct permission rather than PermOrgAdmin
	// (which only the owner holds).
	PermPolicyWrite = "policy.write"
)

// rolePermissions is the single source of truth for authorization.
// owner: everything. admin: members, devices, audit. member: read-only devices.
var rolePermissions = map[string]map[string]bool{
	"owner": {
		PermOrgAdmin:     true,
		PermMemberManage: true,
		PermDeviceRead:   true,
		PermDeviceWrite:  true,
		PermAuditRead:    true,
		PermAddressBook:  true,
		PermPolicyWrite:  true,
	},
	"admin": {
		PermMemberManage: true,
		PermDeviceRead:   true,
		PermDeviceWrite:  true,
		PermAuditRead:    true,
		PermAddressBook:  true,
		PermPolicyWrite:  true,
	},
	"member": {
		PermDeviceRead: true,
	},
}

// Can reports whether the role grants the permission.
func Can(role, perm string) bool {
	perms, ok := rolePermissions[role]
	if !ok {
		return false
	}
	return perms[perm]
}

// Require returns an error when the role does not grant the permission.
func Require(role, perm string) error {
	if !Can(role, perm) {
		return fmt.Errorf("role %q is not allowed to %s", role, perm)
	}
	return nil
}
