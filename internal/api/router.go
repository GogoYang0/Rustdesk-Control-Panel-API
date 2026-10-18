package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
)

// publicPaths never require a bearer token.
var publicPaths = map[string]bool{
	"/healthz":                   true,
	"/api/v1/auth/login":         true,
	"/api/v1/auth/refresh":       true,
	"/api/v1/invitations/accept": true,
}

// NewRouter mounts the generated handlers behind the fixed middleware chain:
// audit log -> JWT auth (except public paths) -> handlers.
func NewRouter(d Deps) *gin.Engine {
	if d.Auditor == nil {
		d.Auditor = audit.Nop{}
	}

	r := gin.New()
	// No reverse proxy is assumed; trusting all proxies would let clients spoof
	// X-Forwarded-For and dodge the per-IP login limits.
	_ = r.SetTrustedProxies(nil)
	r.Use(gin.Recovery())
	r.Use(newAuditMiddleware(d.Auditor))
	r.Use(requireJWTUnlessPublic(d.Issuer))

	gen.RegisterHandlers(r, NewAdminAPI(d))
	return r
}

// requireJWTUnlessPublic validates the bearer token for every non-public path.
func requireJWTUnlessPublic(issuer *auth.Issuer) gin.HandlerFunc {
	jwt := auth.RequireJWT(issuer)
	return func(c *gin.Context) {
		if publicPaths[c.FullPath()] {
			c.Next()
			return
		}
		jwt(c)
	}
}

// requireUserID returns the authenticated user id or aborts with 401.
func requireUserID(c *gin.Context) (uint, bool) {
	uid, ok := auth.UserID(c)
	if !ok {
		abortError(c, http.StatusUnauthorized, gen.ErrorCodeUnauthorized, "authentication required")
		return 0, false
	}
	return uid, true
}

// abortError writes the standard error envelope.
func abortError(c *gin.Context, status int, code gen.ErrorCode, msg string) {
	c.AbortWithStatusJSON(status, gen.ErrorResponse{Code: code, Message: msg})
}
