package auth

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

// ContextUserID is the gin context key holding the authenticated user ID.
const ContextUserID = "auth.userID"

// ContextTokenPermissions is set when the request authenticated with a
// personal token; the API layer intersects these with the live role.
const ContextTokenPermissions = "auth.tokenPermissions"

// RequireJWT rejects requests without a valid access token and stores the
// user ID in the gin context.
func RequireJWT(issuer *Issuer) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		const prefix = "bearer "
		// HTTP auth scheme names are case-insensitive (RFC 7235 §2.1)
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

// RequireJWTOrToken accepts a management access JWT, falling back to a personal
// API token. A personal token is only valid on organization-scoped paths (the
// path orgId must equal the organization the token was issued in): token
// management, organization creation and other non-org endpoints stay JWT-only.
//
// The middleware deliberately stores the token's permission set instead of
// trusting it: the API layer intersects it with the live role on every request
// so a downgraded or disabled membership narrows or kills the token.
func RequireJWTOrToken(issuer *Issuer, tokens *TokenService) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		const prefix = "bearer "
		if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
			c.Header("WWW-Authenticate", `Bearer realm="api"`)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"code": "unauthorized", "message": "missing bearer token"})
			return
		}
		raw := strings.TrimSpace(header[len(prefix):])
		if uid, err := issuer.ParseAccess(raw); err == nil {
			c.Set(ContextUserID, uid)
			c.Next()
			return
		}

		// Fall back to a personal token. Without an organization path there is
		// no tenant to scope it to, so it cannot authenticate. The 32-bit parse
		// bounds the value before it is narrowed to uint (CodeQL integer
		// conversion), and organization ids never exceed that range.
		orgID, perr := strconv.ParseUint(c.Param("orgId"), 10, 32)
		if perr != nil || orgID == 0 || tokens == nil {
			c.Header("WWW-Authenticate", `Bearer realm="api", error="invalid_token"`)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"code": "unauthorized", "message": "invalid or expired token",
			})
			return
		}
		row, err := tokens.Authenticate(c.Request.Context(), raw)
		if err != nil || row.OrganizationID != uint(orgID) {
			c.Header("WWW-Authenticate", `Bearer realm="api", error="invalid_token"`)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"code": "unauthorized", "message": "invalid or expired token",
			})
			return
		}
		c.Set(ContextUserID, row.UserID)
		c.Set(ContextTokenPermissions, row.PermissionList())
		c.Next()
	}
}

// TokenPermissions returns the personal token's requested permission set. Its
// presence marks the request as token-authenticated.
func TokenPermissions(c *gin.Context) ([]string, bool) {
	v, ok := c.Get(ContextTokenPermissions)
	if !ok {
		return nil, false
	}
	perms, ok := v.([]string)
	return perms, ok
}

// IntersectPermissions returns the codes present in both sets, in the order of
// the allowed set. A nil limit is a deny-all (a token with no codes can do
// nothing), never "unlimited".
func IntersectPermissions(allowed, limit []string) []string {
	if limit == nil {
		return []string{}
	}
	keep := make(map[string]bool, len(limit))
	for _, code := range limit {
		keep[code] = true
	}
	out := make([]string, 0, len(allowed))
	for _, code := range allowed {
		if keep[code] {
			out = append(out, code)
		}
	}
	return out
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
