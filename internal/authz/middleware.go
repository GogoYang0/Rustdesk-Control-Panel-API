package authz

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// ContextOrgRole is the gin context key holding the caller's in-org role name
// (display only; authorization uses the permission set below).
const ContextOrgRole = "authz.orgRole"

// ContextOrgPerms is the gin context key holding the caller's permission set.
const ContextOrgPerms = "authz.orgPerms"

// ContextOrgAuditScope is the gin context key holding the caller's role audit
// visibility scope (global or individual).
const ContextOrgAuditScope = "authz.orgAuditScope"

// SetOrgRole stores the caller's membership role name for display.
func SetOrgRole(c *gin.Context, role string) {
	c.Set(ContextOrgRole, role)
}

// SetOrgPermissions stores the caller's effective permission codes.
func SetOrgPermissions(c *gin.Context, perms []string) {
	c.Set(ContextOrgPerms, perms)
}

// SetOrgAuditScope stores the caller's audit visibility scope.
func SetOrgAuditScope(c *gin.Context, scope string) {
	c.Set(ContextOrgAuditScope, scope)
}

// OrgAuditScope returns the stored audit scope. A missing value fails closed:
// handlers must treat the empty scope as individual, never as global.
func OrgAuditScope(c *gin.Context) (string, bool) {
	v, ok := c.Get(ContextOrgAuditScope)
	if !ok {
		return "", false
	}
	scope, ok := v.(string)
	return scope, ok
}

// OrgRole returns the stored role name, if any.
func OrgRole(c *gin.Context) (string, bool) {
	v, ok := c.Get(ContextOrgRole)
	if !ok {
		return "", false
	}
	role, ok := v.(string)
	return role, ok
}

// OrgPermissions returns the stored permission set.
func OrgPermissions(c *gin.Context) ([]string, bool) {
	v, ok := c.Get(ContextOrgPerms)
	if !ok {
		return nil, false
	}
	perms, ok := v.([]string)
	return perms, ok
}

// RequirePerm rejects the request unless the caller's permission set includes
// perm. A missing set fails closed.
func RequirePerm(perm string) gin.HandlerFunc {
	return func(c *gin.Context) {
		perms, ok := OrgPermissions(c)
		if !ok || !Has(perms, perm) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"code":    "forbidden",
				"message": "insufficient permissions",
			})
			return
		}
		c.Next()
	}
}
