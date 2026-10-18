package api

import (
	"github.com/gin-gonic/gin"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
)

// newAuditMiddleware records every request after the handler ran. The entry
// carries who did what and the resulting status; request bodies are never
// logged so credentials stay out of the audit trail.
func newAuditMiddleware(auditor audit.Auditor) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

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
		_ = auditor.Record(c.Request.Context(), entry)
	}
}
