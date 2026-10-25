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
		// The token claims and the persisted session must describe the same
		// identity: handlers scope their queries by the token's org/user, so
		// authorizing as one identity while checking another must fail closed.
		if uid != session.UserID || orgID != session.OrganizationID {
			abortUnauthorized(c, "session does not match token")
			return
		}
		// Session validity is not membership validity: a login that overlapped
		// a member removal can persist a session after the revocation pass. Re-check
		// the current membership so offboarding closes every consumer path.
		if !s.membershipActive(session.UserID, session.OrganizationID) {
			abortUnauthorized(c, "membership revoked")
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
	if !s.membershipActive(session.UserID, session.OrganizationID) {
		return nil, false
	}
	return &session, true
}

// membershipActive reports whether the session owner still belongs to the
// organization with an active (not disabled) membership. The query goes through
// the tenant scope, so the organization filter is injected by the plugin (a
// zero orgID matches nothing) and the membership lookup can never leave the
// session's tenant. A lookup failure is treated as inactive: a revoked or
// disabled membership must never be masked by an unavailable database.
func (s *Server) membershipActive(userID, orgID uint) bool {
	var membership model.Membership
	err := store.ScopedByOrg(s.deps.DB, orgID).
		Select("id").
		Where("user_id = ? AND disabled = ?", userID, false).
		First(&membership).Error
	return err == nil
}
