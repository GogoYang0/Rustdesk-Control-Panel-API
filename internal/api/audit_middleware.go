package api

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
)

// contextAuditRecorded marks that the handler already wrote the audit entry
// inside its own entity transaction (issue #19); the middleware then skips
// its fallback record so the request produces exactly one audit row.
const contextAuditRecorded = "audit.domainRecorded"

// newAuditMiddleware records every request after the handler ran. The entry
// carries who did what and the resulting status; request bodies are never
// logged so credentials stay out of the audit trail.
func newAuditMiddleware(auditor audit.Auditor, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// Domain handlers that record atomically (issue #19) mark the
		// context; their audit row committed with the entity change.
		if _, recorded := c.Get(contextAuditRecorded); recorded {
			return
		}

		entry := audit.Entry{
			Action:     c.Request.Method + " " + c.FullPath(),
			TargetType: "http",
			Detail:     map[string]any{"status": c.Writer.Status()},
		}
		if uid, ok := auth.UserID(c); ok {
			entry.ActorUserID = uid
		}
		if orgID, ok := c.Get(contextOrgID); ok {
			if v, ok := orgID.(uint); ok {
				entry.OrganizationID = v
			}
		}
		// Audit integrity matters: a dropped record must at least leave a
		// trace in the operational log so operators can investigate.
		if err := auditor.Record(c.Request.Context(), entry); err != nil {
			logger.Error("audit record failed",
				zap.Uint("org_id", entry.OrganizationID),
				zap.String("action", entry.Action),
				zap.Error(err))
		}
	}
}
