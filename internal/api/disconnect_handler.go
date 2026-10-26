package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/strategy"
)

// disconnectResponse maps a stored request onto the wire shape.
func disconnectResponse(row *model.DeviceDisconnect) gen.DeviceDisconnect {
	count := row.ConnCount
	return gen.DeviceDisconnect{
		Id:          int64(row.ID),
		DeviceId:    int64(row.DeviceID),
		Reason:      row.Reason,
		Status:      gen.DeviceDisconnectStatus(row.Status),
		RequestedAt: row.RequestedAt,
		FulfilledAt: row.FulfilledAt,
		ExpiresAt:   row.ExpiresAt,
		ConnCount:   &count,
	}
}

// RequestDeviceDisconnect records the intent to drop a device's live
// connections. The client executes it on its next heartbeat (design D4); the
// panel never closes a connection itself.
func (a *AdminAPI) RequestDeviceDisconnect(c *gin.Context, orgId, deviceId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || deviceId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization or device id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermDeviceDisconnect) {
		return
	}
	var req gen.DeviceDisconnectRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid disconnect payload")
		return
	}
	row, err := a.deps.Strategies.RequestDisconnect(c.Request.Context(), uint(orgId), uid, uint(deviceId), req.Reason)
	if err != nil {
		switch {
		case errors.Is(err, strategy.ErrDisconnectPending):
			abortError(c, http.StatusConflict, gen.ErrorCodeConflict,
				"a disconnect request is already pending for this device")
		case errors.Is(err, strategy.ErrInvalidReason):
			abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "reason is required (1-255 characters)")
		default:
			a.writeStrategyError(c, err, "request device disconnect failed")
		}
		return
	}
	// The service wrote the audit entry on the entity transaction.
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusCreated, gen.DeviceDisconnectResponse{
		Code:    gen.ErrorCodeOk,
		Message: "requested",
		Data:    disconnectResponse(row),
	})
}
