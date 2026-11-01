package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/device"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
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
		Name:         req.Name,
		RustdeskID:   req.RustdeskId,
		AllowRestore: true,
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
		Data:    a.deviceToAPI(dev, a.ownerEmailsFor(dev)),
	})
}

// DeleteDevice soft-deletes a device while keeping its history. An open
// session blocks deletion; the operator must end it first.
func (a *AdminAPI) DeleteDevice(c *gin.Context, orgId int64, deviceId int64) {
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
	err := a.deps.Devices.Delete(c.Request.Context(), uint(orgId), uint(deviceId), uid)
	switch {
	case errors.Is(err, device.ErrDeviceNotFound):
		abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, "device not found")
		return
	case errors.Is(err, device.ErrDeviceHasOpenSessions):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "end open sessions before deleting the device")
		return
	case errors.Is(err, device.ErrInvalidInput):
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, err.Error())
		return
	case err != nil:
		a.deps.Logger.Error("delete device failed", zap.Error(err))
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not delete device")
		return
	}
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.OkResponse{Code: gen.ErrorCodeOk, Message: "ok"})
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
		Data:    a.deviceToAPI(dev, a.ownerEmailsFor(dev)),
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
	emails := a.ownerEmails(items)
	for i := range items {
		views = append(views, a.deviceToAPI(&items[i], emails))
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
		Data:    a.deviceToAPI(dev, a.ownerEmailsFor(dev)),
	})
}

// UpdateDevice applies the requested fields of a device update — disabled,
// owner_user_id and note — in one call to the service, which commits every
// change together with its audit rows. A request that names several fields
// either takes effect in full or not at all, so a client is never told the
// request failed while part of it was applied.
func (a *AdminAPI) UpdateDevice(c *gin.Context, orgId int64, deviceId int64) {
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

	var body map[string]json.RawMessage
	if err := c.ShouldBindJSON(&body); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid request body")
		return
	}
	in, err := parseDeviceUpdate(body)
	if err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, err.Error())
		return
	}

	dev, err := a.deps.Devices.Update(c.Request.Context(), uint(orgId), uint(deviceId), uid, in)
	switch {
	case errors.Is(err, device.ErrDeviceNotFound):
		abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, "device not found")
		return
	case errors.Is(err, device.ErrOwnerNotMember):
		// 404, not 400: the answer must not confirm whether the id names a
		// user outside this organization at all.
		abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, "owner is not an active member")
		return
	case errors.Is(err, device.ErrInvalidInput):
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, err.Error())
		return
	case err != nil:
		a.deps.Logger.Error("update device failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not update device")
		return
	}

	// The domain entries committed with the changes; suppress the
	// request-level fallback so one request never adds a second row.
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.DeviceResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data:    a.deviceToAPI(dev, a.ownerEmailsFor(dev)),
	})
}

// parseDeviceUpdate reads the PATCH body into a service input. Presence is
// tracked separately from the value: JSON null clears a nullable field, an
// absent key leaves it alone, and a pointer field alone cannot tell the two
// apart. At least one updatable field is required — an empty object, a body of
// unknown keys and a missing body are all rejected instead of passing as a
// successful no-op.
func parseDeviceUpdate(body map[string]json.RawMessage) (device.UpdateInput, error) {
	var in device.UpdateInput
	recognised := false
	for key, raw := range body {
		switch key {
		case "disabled":
			recognised = true
			// JSON null is rejected, not read as false: binding null into a bool
			// is a silent no-op that would look like an explicit "enable" and
			// re-enable a device the caller never named.
			if isJSONNull(raw) {
				return in, errors.New("disabled must be a boolean")
			}
			var disabled bool
			if err := json.Unmarshal(raw, &disabled); err != nil {
				return in, errors.New("disabled must be a boolean")
			}
			in.Disabled = &disabled
		case "owner_user_id":
			recognised = true
			owner := uint(0)
			if !isJSONNull(raw) {
				var id int64
				if err := json.Unmarshal(raw, &id); err != nil {
					return in, errors.New("owner_user_id must be a user id or null")
				}
				if id <= 0 {
					return in, errors.New("owner_user_id must be a positive user id or null")
				}
				owner = uint(id)
			}
			in.OwnerUserID = &owner
		case "note":
			recognised = true
			note := ""
			if !isJSONNull(raw) {
				if err := json.Unmarshal(raw, &note); err != nil {
					return in, errors.New("note must be a string or null")
				}
			}
			in.Note = &note
		}
	}
	if !recognised {
		return in, errors.New("at least one of disabled, owner_user_id or note is required")
	}
	return in, nil
}

// isJSONNull reports whether a raw JSON fragment is the null literal.
func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

// deviceToAPI maps a stored device to the contract representation. ownerEmails
// resolves the owner address for display; a device without an owner — or whose
// owner row is gone — reports null.
func (a *AdminAPI) deviceToAPI(d *model.Device, ownerEmails map[uint]string) gen.Device {
	status := device.Status(d, a.deps.Now())
	note := d.Note
	view := gen.Device{
		Id:            int64(d.ID),
		Name:          d.Name,
		RustdeskId:    d.RustdeskID,
		Status:        gen.DeviceStatus(status),
		LastSeenAt:    d.LastSeenAt,
		Bound:         d.BoundUUID != "",
		Disabled:      d.Disabled,
		DeviceGroupId: deviceGroupIDToAPI(d.DeviceGroupID),
		StrategyId:    strategyIDToAPI(d.StrategyID),
		Note:          &note,
	}
	if d.OwnerUserID != nil {
		ownerID := int64(*d.OwnerUserID)
		view.OwnerUserId = &ownerID
		if email, ok := ownerEmails[*d.OwnerUserID]; ok {
			view.OwnerEmail = &email
		}
	}
	return view
}

// ownerEmails batch-resolves the owners of a device page in one query, so a
// listing never issues a lookup per row. A failed resolution leaves the
// addresses null instead of failing the page.
func (a *AdminAPI) ownerEmails(devices []model.Device) map[uint]string {
	ids := make([]uint, 0, len(devices))
	seen := make(map[uint]bool, len(devices))
	for i := range devices {
		owner := devices[i].OwnerUserID
		if owner == nil || seen[*owner] {
			continue
		}
		seen[*owner] = true
		ids = append(ids, *owner)
	}
	if len(ids) == 0 {
		return nil
	}
	var users []model.User
	if err := store.WithoutTenantScope(a.deps.DB).Where("id IN ?", ids).Find(&users).Error; err != nil {
		a.deps.Logger.Error("load device owners failed")
		return nil
	}
	emails := make(map[uint]string, len(users))
	for i := range users {
		emails[users[i].ID] = users[i].Email
	}
	return emails
}

// ownerEmailsFor resolves the owner address of one device for the single-device
// responses.
func (a *AdminAPI) ownerEmailsFor(d *model.Device) map[uint]string {
	if d == nil || d.OwnerUserID == nil {
		return nil
	}
	var user model.User
	err := store.WithoutTenantScope(a.deps.DB).First(&user, *d.OwnerUserID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		// The owner row is gone: the reference stays as history, the address
		// reports null.
		return nil
	}
	if err != nil {
		a.deps.Logger.Error("load device owner failed")
		return nil
	}
	return map[uint]string{*d.OwnerUserID: user.Email}
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
