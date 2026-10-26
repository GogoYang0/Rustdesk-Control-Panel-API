package authz

import (
	"errors"
	"fmt"
)

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
	// PermAccessManage gates user groups, device groups and access rules. It is
	// not delegable: handing it to a custom role would let that role reshape
	// who can reach which devices.
	PermAccessManage = "access.manage"
	// PermControlRoleManage gates control role CRUD and member assignment. Not
	// delegable for the same reason as access.manage: it decides what an
	// operator may do after connecting.
	PermControlRoleManage = "control_role.manage"
	// PermStrategyManage gates strategy CRUD and assignment. Not delegable:
	// a strategy rewrites the controlled side's client options, i.e. it can
	// disable screen privacy or file transfer for everybody in the group.
	PermStrategyManage = "strategy.manage"
	// PermDeviceDisconnect gates the heartbeat-driven "drop this device's
	// live connections" request. Not delegable: it terminates other people's
	// sessions.
	PermDeviceDisconnect = "device.disconnect"
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
	{PermAccessManage, "Manage user groups, device groups and access rules", false},
	{PermControlRoleManage, "Manage control roles and their member assignments", false},
	{PermStrategyManage, "Manage client strategies and their assignments", false},
	{PermDeviceDisconnect, "Disconnect a device's live connections", false},
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
			PermAccessManage, PermControlRoleManage, PermStrategyManage, PermDeviceDisconnect,
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

// Normalize error sentinels for role building. Handlers map them onto 400/403.
var (
	ErrUnknownPermission      = errors.New("unknown permission code")
	ErrPermissionNotDelegable = errors.New("permission is not delegable")
)

// NormalizePermissions validates every requested code against the catalog and
// returns the set in catalog order without duplicates. Unknown codes fail
// closed instead of being stored and silently granting nothing.
func NormalizePermissions(codes []string) ([]string, error) {
	wanted := make(map[string]bool, len(codes))
	for _, code := range codes {
		known := false
		for _, p := range catalog {
			if p.Code == code {
				known = true
				break
			}
		}
		if !known {
			return nil, fmt.Errorf("%w: %s", ErrUnknownPermission, code)
		}
		wanted[code] = true
	}
	out := make([]string, 0, len(wanted))
	for _, p := range catalog {
		if wanted[p.Code] {
			out = append(out, p.Code)
		}
	}
	return out, nil
}

// ValidateDelegable rejects codes a custom role may not include. Only
// owner-only capabilities (org.admin, role.manage, access.manage) are
// non-delegable.
func ValidateDelegable(codes []string) error {
	for _, code := range codes {
		for _, p := range catalog {
			if p.Code == code && !p.Delegable {
				return fmt.Errorf("%w: %s", ErrPermissionNotDelegable, code)
			}
		}
	}
	return nil
}

// Require returns an error when the permission set does not include the code.
func Require(perms []string, perm string) error {
	if !Has(perms, perm) {
		return fmt.Errorf("permission %q is not granted", perm)
	}
	return nil
}
