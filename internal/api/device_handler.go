package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/device"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// CreateDevice registers (or re-registers) a RustDesk device in the org.
func (a *AdminAPI) CreateDevice(c *gin.Context, orgId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermDeviceWrite) {
		return
	}

	var req gen.DeviceCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.Name == "" || req.RustdeskId == "" {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "name and rustdesk_id are required")
		return
	}

	dev, err := a.deps.Devices.Register(c.Request.Context(), uint(orgId), device.RegisterInput{
		Name:       req.Name,
		RustdeskID: req.RustdeskId,
	})
	if err != nil {
		a.deps.Logger.Error("register device failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not register device")
		return
	}

	c.JSON(http.StatusCreated, gen.DeviceResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data:    a.deviceToAPI(dev),
	})
}

// DeviceHeartbeat records a heartbeat for a device in the org.
func (a *AdminAPI) DeviceHeartbeat(c *gin.Context, orgId int64, deviceId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || deviceId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermDeviceWrite) {
		return
	}

	dev, err := a.deps.Devices.Heartbeat(c.Request.Context(), uint(orgId), uint(deviceId))
	if errors.Is(err, device.ErrDeviceNotFound) {
		abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, "device not found")
		return
	}
	if err != nil {
		a.deps.Logger.Error("device heartbeat failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not record heartbeat")
		return
	}

	c.JSON(http.StatusOK, gen.DeviceResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data:    a.deviceToAPI(dev),
	})
}

// deviceToAPI maps a stored device to the contract representation.
func (a *AdminAPI) deviceToAPI(d *model.Device) gen.Device {
	status := device.Status(d, a.deps.Now())
	return gen.Device{
		Id:         int64(d.ID),
		Name:       d.Name,
		RustdeskId: d.RustdeskID,
		Status:     gen.DeviceStatus(status),
		LastSeenAt: d.LastSeenAt,
	}
}
