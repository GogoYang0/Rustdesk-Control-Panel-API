package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// Bounds mirror the contract's filter maxLength values (runes).
const (
	maxAuditActionLen     = 128
	maxAuditTargetTypeLen = 64
	maxAuditTargetIDLen   = 64
)

// ListAuditLogs returns one page of audit rows. Visibility comes from the
// caller's role audit scope: global sees the organization, individual sees only
// its own actions and user-type rows targeting it. The read is a polled list,
// so it never generates an audit entry of its own.
func (a *AdminAPI) ListAuditLogs(c *gin.Context, orgId int64, params gen.ListAuditLogsParams) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermAuditRead) {
		return
	}

	filter, err := auditFilterFromParams(params)
	if err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, err.Error())
		return
	}
	page, pageSize := audit.NormalizePagination(intParam(params.Page, 1), intParam(params.PageSize, audit.DefaultPageSize))

	scope, _ := authz.OrgAuditScope(c)
	rows, total, err := audit.Query(c.Request.Context(), a.deps.DB, uint(orgId), filter, audit.Viewer{
		Scope:  scope,
		UserID: uid,
	}, page, pageSize)
	if err != nil {
		a.deps.Logger.Error("list audit logs failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not list audit logs")
		return
	}

	items := make([]gen.AuditLog, 0, len(rows))
	for i := range rows {
		items = append(items, auditLogToAPI(&rows[i]))
	}
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.AuditLogListResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data: gen.AuditLogPage{
			Items:    items,
			Page:     page,
			PageSize: int64(pageSize),
			Total:    total,
		},
	})
}

// auditFilterFromParams validates the optional query parameters into the
// domain filter. Lengths are checked here because the generated binder does not
// enforce schema maxLength on query strings.
func auditFilterFromParams(params gen.ListAuditLogsParams) (audit.Filter, error) {
	return auditFilterFromValues(params.Action, params.ActorUserId, params.TargetType, params.TargetId, params.From, params.To)
}

// auditFilterFromValues is the shared filter validation for the list and the
// export endpoints, whose generated param structs differ only in shape.
func auditFilterFromValues(action *string, actorUserID *int64, targetType, targetID *string, from, to *time.Time) (audit.Filter, error) {
	var f audit.Filter
	if action != nil {
		if utf8.RuneCountInString(*action) > maxAuditActionLen {
			return f, errString("action is too long")
		}
		f.Action = *action
	}
	if actorUserID != nil {
		if *actorUserID < 0 {
			return f, errString("actorUserId must not be negative")
		}
		id := uint(*actorUserID)
		f.ActorUserID = &id
	}
	if targetType != nil {
		if utf8.RuneCountInString(*targetType) > maxAuditTargetTypeLen {
			return f, errString("targetType is too long")
		}
		f.TargetType = *targetType
	}
	if targetID != nil {
		if utf8.RuneCountInString(*targetID) > maxAuditTargetIDLen {
			return f, errString("targetId is too long")
		}
		f.TargetID = *targetID
	}
	f.From = from
	f.To = to
	return f, nil
}

// ExportAuditLogs streams the filtered audit rows as CSV. The export is capped
// at audit.CSVLimit rows; a larger result must be narrowed instead of silently
// truncated. The action itself is audited once (not per poll, unlike the list).
func (a *AdminAPI) ExportAuditLogs(c *gin.Context, orgId int64, params gen.ExportAuditLogsParams) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermAuditRead) {
		return
	}

	filter, err := auditFilterFromValues(params.Action, params.ActorUserId, params.TargetType, params.TargetId, params.From, params.To)
	if err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, err.Error())
		return
	}

	scope, _ := authz.OrgAuditScope(c)
	rows, err := audit.QueryAll(c.Request.Context(), a.deps.DB, uint(orgId), filter, audit.Viewer{
		Scope:  scope,
		UserID: uid,
	}, audit.CSVLimit)
	switch {
	case errors.Is(err, audit.ErrExportTooLarge):
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, err.Error())
		return
	case err != nil:
		a.deps.Logger.Error("export audit logs failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not export audit logs")
		return
	}

	var buf bytes.Buffer
	if err := audit.WriteCSV(&buf, rows, a.actorEmails(rows)); err != nil {
		a.deps.Logger.Error("write audit csv failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not export audit logs")
		return
	}

	detail := map[string]any{"rows": len(rows), "format": "csv"}
	if filter.Action != "" {
		detail["action"] = filter.Action
	}
	if filter.ActorUserID != nil {
		detail["actor_user_id"] = *filter.ActorUserID
	}
	if filter.TargetType != "" {
		detail["target_type"] = filter.TargetType
	}
	if filter.TargetID != "" {
		detail["target_id"] = filter.TargetID
	}
	if filter.From != nil {
		detail["from"] = filter.From.UTC()
	}
	if filter.To != nil {
		detail["to"] = filter.To.UTC()
	}
	if err := a.deps.Auditor.Record(c.Request.Context(), audit.Entry{
		OrganizationID: uint(orgId),
		ActorUserID:    uid,
		Action:         "audit.export",
		TargetType:     "audit_log",
		Detail:         detail,
	}); err != nil {
		// An export is data leaving the system; one that cannot be traced must
		// not be served (fail closed).
		a.deps.Logger.Error("audit export record failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not record the export")
		return
	}

	c.Header("Cache-Control", "no-store")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"audit-org-%d-%s.csv\"",
		orgId, a.deps.Now().UTC().Format("20060102T150405Z")))
	c.Set(contextAuditRecorded, true)
	c.Data(http.StatusOK, "text/csv; charset=utf-8", buf.Bytes())
}

// actorEmails resolves the actor ids of the exported rows for the actor_email
// column. A lookup failure is not fatal to the export: the column degrades to
// empty rather than withholding the trail the caller is authorized to read.
func (a *AdminAPI) actorEmails(rows []model.AuditLog) map[uint]string {
	ids := make([]uint, 0, len(rows))
	seen := map[uint]bool{}
	for _, row := range rows {
		if row.ActorUserID != 0 && !seen[row.ActorUserID] {
			seen[row.ActorUserID] = true
			ids = append(ids, row.ActorUserID)
		}
	}
	out := make(map[uint]string, len(ids))
	if len(ids) == 0 {
		return out
	}
	var users []model.User
	if err := a.deps.DB.Where("id IN ?", ids).Find(&users).Error; err != nil {
		a.deps.Logger.Warn("load actor emails failed")
		return out
	}
	for _, u := range users {
		out[u.ID] = u.Email
	}
	return out
}

// auditLogToAPI maps a stored row onto the wire shape, decoding detail into a
// JSON value and falling back to the raw string when history is not JSON.
func auditLogToAPI(row *model.AuditLog) gen.AuditLog {
	return gen.AuditLog{
		Id:          int64(row.ID),
		Seq:         int64(row.Seq),
		ActorUserId: int64(row.ActorUserID),
		Action:      row.Action,
		TargetType:  row.TargetType,
		TargetId:    row.TargetID,
		Detail:      parseAuditDetail(row.Detail),
		CreatedAt:   row.CreatedAt,
	}
}

// GetAuditRetention returns the organization's retention window and the latest
// archive summary. Reading is owner-only and polled, so it is not audited.
func (a *AdminAPI) GetAuditRetention(c *gin.Context, orgId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermOrgAdmin) {
		return
	}
	days, err := a.retention.Get(c.Request.Context(), uint(orgId))
	if err != nil {
		a.writeRetentionError(c, err, "load audit retention failed")
		return
	}
	latest, err := a.retention.Latest(c.Request.Context(), uint(orgId))
	if err != nil {
		a.writeRetentionError(c, err, "load audit archive status failed")
		return
	}
	data := gen.AuditRetention{AuditRetentionDays: days}
	if latest.Found {
		summary := map[string]any{"at": latest.At, "rows": latest.Rows, "path": latest.Path}
		data.LastArchive = &summary
	}
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.AuditRetentionResponse{Code: gen.ErrorCodeOk, Message: "ok", Data: data})
}

// SetAuditRetention updates the retention window; the update and its audit entry
// commit together.
func (a *AdminAPI) SetAuditRetention(c *gin.Context, orgId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermOrgAdmin) {
		return
	}
	var req gen.AuditRetentionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "days is required")
		return
	}

	err := a.deps.DB.Transaction(func(tx *gorm.DB) error {
		if err := a.retention.SetDaysTx(tx, uint(orgId), req.Days); err != nil {
			return err
		}
		tr, ok := a.deps.Auditor.(audit.TxRecorder)
		if !ok {
			return errAuditUnavailable
		}
		return tr.RecordTx(tx, audit.Entry{
			OrganizationID: uint(orgId),
			ActorUserID:    uid,
			Action:         "organization.audit_retention.set",
			TargetType:     "organization",
			TargetID:       fmt.Sprint(orgId),
			Detail:         map[string]any{"days": req.Days},
		})
	})
	switch {
	case errors.Is(err, audit.ErrInvalidRetention):
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, err.Error())
		return
	case errors.Is(err, gorm.ErrRecordNotFound):
		abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, "organization not found")
		return
	case errors.Is(err, errAuditUnavailable):
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "audit unavailable")
		return
	case err != nil:
		a.deps.Logger.Error("set audit retention failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not update audit retention")
		return
	}

	days, err := a.retention.Get(c.Request.Context(), uint(orgId))
	if err != nil {
		a.writeRetentionError(c, err, "reload audit retention failed")
		return
	}
	latest, err := a.retention.Latest(c.Request.Context(), uint(orgId))
	if err != nil {
		a.writeRetentionError(c, err, "reload audit archive status failed")
		return
	}
	data := gen.AuditRetention{AuditRetentionDays: days}
	if latest.Found {
		summary := map[string]any{"at": latest.At, "rows": latest.Rows, "path": latest.Path}
		data.LastArchive = &summary
	}
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.AuditRetentionResponse{Code: gen.ErrorCodeOk, Message: "ok", Data: data})
}

// writeRetentionError maps retention failures; unknown failures stay opaque.
func (a *AdminAPI) writeRetentionError(c *gin.Context, err error, logMsg string) {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, "organization not found")
		return
	}
	a.deps.Logger.Error(logMsg)
	abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "audit retention operation failed")
}

// parseAuditDetail returns nil for an empty detail, a decoded JSON value when
// the stored text parses, and the original string otherwise.
func parseAuditDetail(raw string) any {
	if raw == "" {
		return nil
	}
	var value any
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		return raw
	}
	return value
}

// errString is a tiny error type for parameter validation messages.
type errString string

func (e errString) Error() string { return string(e) }

// intParam returns a pointer value or its default.
func intParam(v *int, def int) int {
	if v == nil {
		return def
	}
	return *v
}
