package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/compatapi"
)

// publicPaths never require a bearer token.
var publicPaths = map[string]bool{
	"/healthz":                         true,
	"/api/v1/auth/login":               true,
	"/api/v1/auth/refresh":             true,
	"/api/v1/auth/2fa/verify":          true,
	"/api/v1/auth/verify-email":        true,
	"/api/v1/auth/resend-verification": true,
	"/api/v1/invitations/accept":       true,
}

// NewRouter mounts the generated handlers behind the fixed middleware chain:
// audit log -> JWT auth (except public paths) -> handlers.
func NewRouter(d Deps) *gin.Engine {
	if d.Auditor == nil {
		d.Auditor = audit.Nop{}
	}
	// Normalize the logger before the middleware chain is built so audit
	// failures are always observable (NewAdminAPI normalizes it again later).
	if d.Logger == nil {
		d.Logger = zap.NewNop()
	}
	if d.Tokens == nil {
		d.Tokens = auth.NewTokenService(d.DB, d.Now)
	}
	if d.TOTP == nil {
		d.TOTP = auth.NewTOTPService(d.DB, d.AuthSecret, d.Now)
	}
	if d.Retention == nil {
		recorder, _ := d.Auditor.(audit.TxRecorder)
		d.Retention = audit.NewRetentionService(d.DB, "./data/audit-archive", recorder, d.Now)
	}

	r := gin.New()
	// No reverse proxy is assumed; trusting all proxies would let clients spoof
	// X-Forwarded-For and dodge the per-IP login limits.
	_ = r.SetTrustedProxies(nil)
	r.Use(gin.Recovery())
	r.Use(newAuditMiddleware(d.Auditor, d.Logger))

	// Management API: access JWTs, with personal tokens accepted on
	// organization-scoped paths only.
	mgmt := r.Group("")
	mgmt.Use(requireAuthUnlessPublic(d.Issuer, d.Tokens))
	gen.RegisterHandlers(mgmt, NewAdminAPI(d))

	// RustDesk compatibility endpoints beside the management API with their
	// own session authentication: the management JWT middleware must never
	// cover /api/* compat paths (two token families stay interchangeable-
	// proof, and the client's unauthenticated heartbeat still lands).
	compatapi.Mount(r, compatapi.Deps{
		DB:        d.DB,
		Issuer:    d.Issuer,
		Devices:   d.Devices,
		Now:       d.Now,
		AccessTTL: d.CompatTTL,
	})
	return r
}

// requireAuthUnlessPublic validates the bearer credential for every non-public
// path: an access JWT, or a personal token on organization-scoped paths.
func requireAuthUnlessPublic(issuer *auth.Issuer, tokens *auth.TokenService) gin.HandlerFunc {
	credential := auth.RequireJWTOrToken(issuer, tokens)
	return func(c *gin.Context) {
		if publicPaths[c.FullPath()] {
			c.Next()
			return
		}
		credential(c)
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
