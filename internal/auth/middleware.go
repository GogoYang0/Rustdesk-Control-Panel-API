package auth

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// ContextUserID is the gin context key holding the authenticated user ID.
const ContextUserID = "auth.userID"

// RequireJWT rejects requests without a valid access token and stores the
// user ID in the gin context.
func RequireJWT(issuer *Issuer) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		const prefix = "bearer "
		// HTTP 认证方案名不区分大小写（RFC 7235 §2.1）
		if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
			c.Header("WWW-Authenticate", `Bearer realm="api"`)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"code": "unauthorized", "message": "missing bearer token"})
			return
		}
		uid, err := issuer.ParseAccess(strings.TrimSpace(header[len(prefix):]))
		if err != nil {
			c.Header("WWW-Authenticate", `Bearer realm="api", error="invalid_token"`)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"code": "unauthorized", "message": "invalid or expired token"})
			return
		}
		c.Set(ContextUserID, uid)
		c.Next()
	}
}

// UserID returns the authenticated user ID stored by RequireJWT.
func UserID(c *gin.Context) (uint, bool) {
	v, ok := c.Get(ContextUserID)
	if !ok {
		return 0, false
	}
	uid, ok := v.(uint)
	return uid, ok
}
