package api

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// logEventDefaultLimit and logEventMaxLimit mirror the contract bounds.
const (
	logEventDefaultLimit = 50
	logEventMaxLimit     = 200
)

// ListLogEvents answers the collected hbbs/hbbr events of one organization,
// newest first. Filters: deviceId, level, since; the limit is clamped to the
// contract range (1..200, default 50).
func (a *AdminAPI) ListLogEvents(c *gin.Context, orgId int64, params gen.ListLogEventsParams) {
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

	// The contract declares an enum for level and a positive device id; the
	// generated binder does not enforce either, so validate here instead of
	// silently returning an empty list.
	if params.Level != nil {
		switch string(*params.Level) {
		case model.LogLevelInfo, model.LogLevelWarn, model.LogLevelError:
		default:
			abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid level filter")
			return
		}
	}
	if params.DeviceId != nil && *params.DeviceId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid device id")
		return
	}

	limit := logEventDefaultLimit
	if params.Limit != nil {
		limit = *params.Limit
		if limit < 1 {
			limit = 1
		}
		if limit > logEventMaxLimit {
			limit = logEventMaxLimit
		}
	}

	// Every query goes through the scoped handle: the tenant plugin fails
	// closed, so a bug cannot leak another organization's events.
	q := store.ScopedByOrg(a.deps.DB, uint(orgId)).Model(&model.LogEvent{})
	// Individual audit scope sees events from devices it owns. Events without
	// a resolved device (device_id NULL) cannot be attributed, so they are
	// hidden rather than guessed. A missing scope falls closed to individual.
	scope, _ := authz.OrgAuditScope(c)
	if scope != model.AuditScopeGlobal {
		owned := store.ScopedByOrg(a.deps.DB, uint(orgId)).Model(&model.Device{}).
			Select("id").Where("owner_user_id = ?", uid)
		q = q.Where("device_id IN (?)", owned)
	}
	if params.DeviceId != nil {
		q = q.Where("device_id = ?", *params.DeviceId)
	}
	if params.Level != nil {
		q = q.Where("level = ?", string(*params.Level))
	}
	if params.Since != nil {
		// SQLite keeps time.Time as text and compares it lexicographically, so
		// a cutoff with an offset ("03:00:00+00:00") would not order correctly
		// against a row stored as "10:00:00+08:00". Compare instants instead.
		q = q.Where("occurred_at >= ?", params.Since.UTC())
	}

	var rows []model.LogEvent
	if err := q.Order("occurred_at DESC, id DESC").Limit(limit).Find(&rows).Error; err != nil {
		a.deps.Logger.Error("list log events failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not list log events")
		return
	}

	data := make([]gen.LogEvent, 0, len(rows))
	for _, row := range rows {
		event := gen.LogEvent{
			Id:         int64(row.ID),
			Source:     gen.LogEventSource(row.Source),
			Level:      gen.LogEventLevel(row.Level),
			Kind:       gen.LogEventKind(row.Kind),
			OccurredAt: row.OccurredAt,
		}
		if row.DeviceID != nil {
			id := int64(*row.DeviceID)
			event.DeviceId = &id
		}
		if row.DetailJSON != "" && row.DetailJSON != "{}" {
			var detail map[string]any
			if err := json.Unmarshal([]byte(row.DetailJSON), &detail); err == nil && len(detail) > 0 {
				event.Detail = &detail
			}
		}
		data = append(data, event)
	}

	c.JSON(http.StatusOK, gen.LogEventListResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data:    data,
	})
}
