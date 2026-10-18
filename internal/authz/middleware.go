package authz

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// ContextOrgRole is the gin context key holding the caller's in-org role.
const ContextOrgRole = "authz.orgRole"

// SetOrgRole stores the caller's membership role for later permission checks.
func SetOrgRole(c *gin.Context, role string) {
	c.Set(ContextOrgRole, role)
}

// OrgRole returns the stored role, if any.
func OrgRole(c *gin.Context) (string, bool) {
	v, ok := c.Get(ContextOrgRole)
	if !ok {
		return "", false
	}
	role, ok := v.(string)
	return role, ok
}

// RequirePerm rejects the request unless the caller's role grants perm.
func RequirePerm(perm string) gin.HandlerFunc {
	return func(c *gin.Context) {
		role, ok := OrgRole(c)
		if !ok || !Can(role, perm) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"code":    "forbidden",
				"message": "insufficient permissions",
			})
			return
		}
		c.Next()
	}
}
