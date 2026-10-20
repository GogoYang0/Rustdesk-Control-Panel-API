package compatapi

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// requireSession validates a Bearer compat token and its persisted session:
// the token must carry the compat audience, and the referenced session must
// exist, be unexpired and unrevoked. Management tokens never pass here.
func (s *Server) requireSession() gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		const prefix = "bearer "
		if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
			abortUnauthorized(c, "missing bearer token")
			return
		}
		uid, orgID, jti, err := s.deps.Issuer.ParseCompat(strings.TrimSpace(header[len(prefix):]))
		if err != nil {
			abortUnauthorized(c, "invalid or expired token")
			return
		}
		var session model.CompatSession
		if err := store.WithoutTenantScope(s.deps.DB).
			Where("jti = ?", jti).
			First(&session).Error; err != nil {
			abortUnauthorized(c, "session not found")
			return
		}
		if !session.Active(s.deps.Now()) {
			abortUnauthorized(c, "session revoked or expired")
			return
		}
		c.Set(ContextUserID, uid)
		c.Set(ContextOrgID, orgID)
		c.Set(ContextJTI, jti)
		c.Next()
	}
}

// abortUnauthorized answers 401; the client reacts by prompting for login.
func abortUnauthorized(c *gin.Context, msg string) {
	c.Header("WWW-Authenticate", `Bearer realm="compat"`)
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": msg})
}

// sessionFrom returns the authenticated identity stored by requireSession.
func sessionFrom(c *gin.Context) (uid, orgID uint, jti string) {
	if v, ok := c.Get(ContextUserID); ok {
		uid, _ = v.(uint)
	}
	if v, ok := c.Get(ContextOrgID); ok {
		orgID, _ = v.(uint)
	}
	if v, ok := c.Get(ContextJTI); ok {
		jti, _ = v.(string)
	}
	return uid, orgID, jti
}

// activeSessionByUUID returns the still-active session bound to the given
// device UUID and rustdesk id (used by the unauthenticated heartbeat/sysinfo
// calls: the client posted its device binding at login, the session fixes the
// org). The device id is part of the lookup on purpose: the uuid is neither a
// secret nor verified at login, so filtering by uuid alone would let any
// account shadow another device's session and suppress its heartbeat.
func (s *Server) activeSessionByUUID(uuid, deviceID string) (*model.CompatSession, bool) {
	if uuid == "" || deviceID == "" {
		return nil, false
	}
	var session model.CompatSession
	if err := store.WithoutTenantScope(s.deps.DB).
		Where("uuid = ? AND device_id = ? AND revoked_at IS NULL AND expires_at > ?",
			uuid, deviceID, s.deps.Now()).
		Order("id DESC").
		First(&session).Error; err != nil {
		return nil, false
	}
	if !session.Active(s.deps.Now()) {
		return nil, false
	}
	return &session, true
}
