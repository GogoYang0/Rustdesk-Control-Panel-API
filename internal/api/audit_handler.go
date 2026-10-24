package api

import (
	"encoding/json"
	"net/http"
	"unicode/utf8"

	"github.com/gin-gonic/gin"

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
	var f audit.Filter
	if params.Action != nil {
		if utf8.RuneCountInString(*params.Action) > maxAuditActionLen {
			return f, errString("action is too long")
		}
		f.Action = *params.Action
	}
	if params.ActorUserId != nil {
		if *params.ActorUserId < 0 {
			return f, errString("actorUserId must not be negative")
		}
		id := uint(*params.ActorUserId)
		f.ActorUserID = &id
	}
	if params.TargetType != nil {
		if utf8.RuneCountInString(*params.TargetType) > maxAuditTargetTypeLen {
			return f, errString("targetType is too long")
		}
		f.TargetType = *params.TargetType
	}
	if params.TargetId != nil {
		if utf8.RuneCountInString(*params.TargetId) > maxAuditTargetIDLen {
			return f, errString("targetId is too long")
		}
		f.TargetID = *params.TargetId
	}
	f.From = params.From
	f.To = params.To
	return f, nil
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
