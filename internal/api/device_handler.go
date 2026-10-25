package api

import (
	"errors"
	"net/http"
	"unicode/utf8"

	"github.com/gin-gonic/gin"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/device"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// maxDeviceQueryLen mirrors the contract's q maxLength (runes).
const maxDeviceQueryLen = 64

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
	if errors.Is(err, device.ErrInvalidInput) {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, err.Error())
		return
	}
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
	switch {
	case errors.Is(err, device.ErrDeviceNotFound):
		abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, "device not found")
		return
	case errors.Is(err, device.ErrDeviceDisabled):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "device is disabled")
		return
	case err != nil:
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

// ListDevices returns one page of the organization's devices.
//
// Reading is member-level. This is a polled read, so the handler marks the
// request as already audited: otherwise a dashboard refreshing every few
// seconds writes an audit row per poll (#19).
func (a *AdminAPI) ListDevices(c *gin.Context, orgId int64, params gen.ListDevicesParams) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermDeviceRead) {
		return
	}

	filter := device.DeviceFilter{
		Bound: params.Bound,
	}
	if params.Q != nil {
		if utf8.RuneCountInString(*params.Q) > maxDeviceQueryLen {
			abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "q is too long")
			return
		}
		filter.Query = *params.Q
	}
	if params.Page != nil {
		filter.Page = *params.Page
	}
	if params.PageSize != nil {
		filter.PageSize = *params.PageSize
	}

	items, total, err := a.deps.Devices.List(c.Request.Context(), uint(orgId), filter)
	if err != nil {
		a.deps.Logger.Error("list devices failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not list devices")
		return
	}

	views := make([]gen.Device, 0, len(items))
	for i := range items {
		views = append(views, a.deviceToAPI(&items[i]))
	}
	page, pageSize := filter.NormalisedPagination()

	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.DeviceListResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data: gen.DevicePage{
			Items:    views,
			Page:     page,
			PageSize: int64(pageSize),
			Total:    total,
		},
	})
}

// ResetDeviceBinding clears the device binding, advances the binding
// generation and records the operator's reason in the same transaction.
func (a *AdminAPI) ResetDeviceBinding(c *gin.Context, orgId int64, deviceId int64) {
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

	var req gen.DeviceRebindRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "reason is required")
		return
	}

	dev, err := a.deps.Devices.ResetBinding(c.Request.Context(), uint(orgId), uint(deviceId), uid, req.Reason)
	switch {
	case errors.Is(err, device.ErrInvalidInput):
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, err.Error())
		return
	case errors.Is(err, device.ErrDeviceNotFound):
		abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, "device not found")
		return
	case err != nil:
		a.deps.Logger.Error("reset device binding failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not reset device binding")
		return
	}

	// The domain entry committed with the binding change; suppress the
	// request-level fallback so one reset produces exactly one audit row.
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.DeviceResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data:    a.deviceToAPI(dev),
	})
}

// SetDeviceDisabled stops or restores a device. The service revokes the
// device's active compat sessions and records the audit entry in one
// transaction, so one call produces exactly one audit row.
func (a *AdminAPI) SetDeviceDisabled(c *gin.Context, orgId int64, deviceId int64) {
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

	var req gen.DeviceDisableRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "disabled is required")
		return
	}

	dev, err := a.deps.Devices.SetDisabled(c.Request.Context(), uint(orgId), uint(deviceId), uid, req.Disabled)
	switch {
	case errors.Is(err, device.ErrDeviceNotFound):
		abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, "device not found")
		return
	case errors.Is(err, device.ErrInvalidInput):
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, err.Error())
		return
	case err != nil:
		a.deps.Logger.Error("set device disabled failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not update device")
		return
	}

	c.Set(contextAuditRecorded, true)
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
		Id:            int64(d.ID),
		Name:          d.Name,
		RustdeskId:    d.RustdeskID,
		Status:        gen.DeviceStatus(status),
		LastSeenAt:    d.LastSeenAt,
		Bound:         d.BoundUUID != "",
		Disabled:      d.Disabled,
		DeviceGroupId: deviceGroupIDToAPI(d.DeviceGroupID),
	}
}

// deviceGroupIDToAPI maps the nullable group reference onto the contract's
// nullable int64 (0 is never a valid group id, so a nil pointer stays null).
func deviceGroupIDToAPI(v *uint) *int64 {
	if v == nil {
		return nil
	}
	out := int64(*v)
	return &out
}
