package authz_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
)

func TestRoleMatrix(t *testing.T) {
	cases := []struct {
		name    string
		role    string
		perm    string
		allowed bool
	}{
		{"owner can administer org", "owner", authz.PermOrgAdmin, true},
		{"owner can manage members", "owner", authz.PermMemberManage, true},
		{"owner can write devices", "owner", authz.PermDeviceWrite, true},
		{"owner can read audit", "owner", authz.PermAuditRead, true},

		{"admin cannot administer org", "admin", authz.PermOrgAdmin, false},
		{"admin can manage members", "admin", authz.PermMemberManage, true},
		{"admin can write devices", "admin", authz.PermDeviceWrite, true},
		{"admin can read audit", "admin", authz.PermAuditRead, true},

		{"member cannot administer org", "member", authz.PermOrgAdmin, false},
		{"member cannot manage members", "member", authz.PermMemberManage, false},
		{"member cannot write devices", "member", authz.PermDeviceWrite, false},
		{"member cannot read audit", "member", authz.PermAuditRead, false},
		{"member can read devices", "member", authz.PermDeviceRead, true},

		{"unknown role has no access", "intern", authz.PermDeviceRead, false},
		{"unknown permission is denied", "owner", "org.nuke", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.allowed, authz.Has(authz.BuiltinPermissions(c.role), c.perm))
		})
	}
}

func TestRequire_ReturnsErrorWhenForbidden(t *testing.T) {
	require.NoError(t, authz.Require(authz.BuiltinPermissions("owner"), authz.PermOrgAdmin))
	require.Error(t, authz.Require(authz.BuiltinPermissions("member"), authz.PermMemberManage))
}
