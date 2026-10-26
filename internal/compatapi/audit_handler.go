package compatapi

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/logquery"
)

// maxAuditBodyBytes bounds the client payload: real records are a few hundred
// bytes, and nothing about the protocol needs a larger body.
const maxAuditBodyBytes = 64 << 10

// bindAudit decodes one audit payload, refusing oversized bodies before JSON
// parsing allocates them.
func bindAudit(c *gin.Context, out any) bool {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxAuditBodyBytes)
	if err := c.ShouldBindJSON(out); err != nil {
		compatError(c, http.StatusBadRequest, "invalid audit payload")
		return false
	}
	return true
}

// writeAuditResult maps ingest outcomes onto the client's error envelope. A
// duplicate nonce is a success: the client retried a record that already
// landed, and answering 200 stops the retry loop.
func writeAuditResult(c *gin.Context, _ bool, err error) {
	switch {
	case err == nil:
		ok(c)
	case errors.Is(err, logquery.ErrMalformed):
		compatError(c, http.StatusBadRequest, "invalid audit payload")
	case errors.Is(err, logquery.ErrUnknownDevice):
		compatError(c, http.StatusForbidden, "unknown device; sign in from the client first")
	case errors.Is(err, logquery.ErrIdentityMismatch):
		compatError(c, http.StatusForbidden, "device identity does not match its binding")
	default:
		compatError(c, http.StatusInternalServerError, "could not record audit report")
	}
}

// auditConn accepts the connection lifecycle reports and the note-only body the
// client's "send note" action produces.
func (s *Server) auditConn(c *gin.Context) {
	var p logquery.ConnPayload
	if !bindAudit(c, &p) {
		return
	}
	dedup, err := s.deps.AuditIngest.Conn(c.Request.Context(), p)
	writeAuditResult(c, dedup, err)
}

// auditFile accepts one file-transfer report.
func (s *Server) auditFile(c *gin.Context) {
	var p logquery.FilePayload
	if !bindAudit(c, &p) {
		return
	}
	dedup, err := s.deps.AuditIngest.File(c.Request.Context(), p)
	writeAuditResult(c, dedup, err)
}

// auditAlarm accepts one client security alarm.
func (s *Server) auditAlarm(c *gin.Context) {
	var p logquery.AlarmPayload
	if !bindAudit(c, &p) {
		return
	}
	dedup, err := s.deps.AuditIngest.Alarm(c.Request.Context(), p)
	writeAuditResult(c, dedup, err)
}
