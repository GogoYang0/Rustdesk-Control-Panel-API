package api

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
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
	if _, member := a.membershipFor(c, uid, uint(orgId)); !member {
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
	if params.DeviceId != nil {
		q = q.Where("device_id = ?", *params.DeviceId)
	}
	if params.Level != nil {
		q = q.Where("level = ?", string(*params.Level))
	}
	if params.Since != nil {
		q = q.Where("occurred_at >= ?", *params.Since)
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
