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
	// PermApprovalDecide gates approve/deny decisions. The contract grants it
	// to owner and admin — members submit requests but cannot rule on them.
	PermApprovalDecide = "approval.decide"
	// PermRoleManage gates role CRUD and assignment. It is owner-only and not
	// delegable: a custom role must never be able to edit the role table.
	PermRoleManage = "role.manage"
)

// Permission is one entry of the catalog served to role builders.
type Permission struct {
	Code        string
	Description string
	Delegable   bool
}

// catalog is the single source of truth for permission codes. Delegable marks
// the codes a custom role may include; the rest are owner-only capabilities.
var catalog = []Permission{
	{PermOrgAdmin, "Administer organization settings and provisioning", false},
	{PermRoleManage, "Create, edit, delete, and assign roles", false},
	{PermMemberManage, "Invite and remove members, disable memberships", true},
	{PermDeviceRead, "Read devices", true},
	{PermDeviceWrite, "Register devices, heartbeat, rebind, disable", true},
	{PermAuditRead, "Read and export audit logs", true},
	{PermAddressBook, "Write shared address books", true},
	{PermPolicyWrite, "Manage connection policies", true},
	{PermApprovalDecide, "Approve or deny connection approvals", true},
}

// Catalog returns the permission catalog in a stable order.
func Catalog() []Permission {
	out := make([]Permission, len(catalog))
	copy(out, catalog)
	return out
}

// AllPermissionCodes returns every code; the owner role holds exactly this set.
func AllPermissionCodes() []string {
	out := make([]string, 0, len(catalog))
	for _, p := range catalog {
		out = append(out, p.Code)
	}
	return out
}

// Delegable reports whether a custom role may include the code.
func Delegable(code string) bool {
	for _, p := range catalog {
		if p.Code == code {
			return p.Delegable
		}
	}
	return false
}

// BuiltinPermissions returns the fixed permission set of a builtin role kind.
// Custom roles always resolve from the roles table instead.
func BuiltinPermissions(kind string) []string {
	switch kind {
	case "owner":
		return AllPermissionCodes()
	case "admin":
		return []string{
			PermMemberManage, PermDeviceRead, PermDeviceWrite,
			PermAuditRead, PermAddressBook, PermPolicyWrite, PermApprovalDecide,
		}
	case "member":
		return []string{PermDeviceRead}
	default:
		return nil
	}
}

// Has reports whether the permission set includes the code. A nil set denies.
func Has(perms []string, perm string) bool {
	for _, p := range perms {
		if p == perm {
			return true
		}
	}
	return false
}

// Require returns an error when the permission set does not include the code.
func Require(perms []string, perm string) error {
	if !Has(perms, perm) {
		return fmt.Errorf("permission %q is not granted", perm)
	}
	return nil
}
