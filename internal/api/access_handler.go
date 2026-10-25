package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/access"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// userGroupToAPI maps one group view onto the contract shape.
func userGroupToAPI(view access.GroupView) gen.UserGroup {
	ids := make([]int64, 0, len(view.MemberIDs))
	for _, id := range view.MemberIDs {
		ids = append(ids, int64(id))
	}
	return gen.UserGroup{
		Id:        int64(view.Group.ID),
		Name:      view.Group.Name,
		Kind:      gen.UserGroupKind(view.Group.Kind),
		MemberIds: ids,
		CreatedAt: view.Group.CreatedAt,
		UpdatedAt: view.Group.UpdatedAt,
	}
}

// ListUserGroups lists the organization's user groups.
func (a *AdminAPI) ListUserGroups(c *gin.Context, orgId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermAccessManage) {
		return
	}
	views, err := a.deps.Access.ListUserGroups(c.Request.Context(), uint(orgId))
	if err != nil {
		a.deps.Logger.Error("list user groups failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not list user groups")
		return
	}
	out := make([]gen.UserGroup, 0, len(views))
	for _, view := range views {
		out = append(out, userGroupToAPI(view))
	}
	c.JSON(http.StatusOK, gen.UserGroupListResponse{Code: gen.ErrorCodeOk, Message: "ok", Data: out})
}

// CreateUserGroup adds a custom user group.
func (a *AdminAPI) CreateUserGroup(c *gin.Context, orgId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermAccessManage) {
		return
	}
	var req gen.UserGroupCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid user group body")
		return
	}
	group, err := a.deps.Access.CreateUserGroup(c.Request.Context(), uint(orgId), uid, req.Name)
	if err != nil {
		a.writeAccessError(c, err, "create user group failed")
		return
	}
	view, err := a.deps.Access.UserGroupView(c.Request.Context(), uint(orgId), group.ID)
	if err != nil {
		a.writeAccessError(c, err, "reload created user group failed")
		return
	}
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusCreated, gen.UserGroupResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data:    userGroupToAPI(view),
	})
}

// RenameUserGroup renames a custom user group.
func (a *AdminAPI) RenameUserGroup(c *gin.Context, orgId int64, groupId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || groupId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermAccessManage) {
		return
	}
	var req gen.UserGroupRenameRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid user group body")
		return
	}
	group, err := a.deps.Access.RenameUserGroup(c.Request.Context(), uint(orgId), uid, uint(groupId), req.Name)
	if err != nil {
		a.writeAccessError(c, err, "rename user group failed")
		return
	}
	view, err := a.deps.Access.UserGroupView(c.Request.Context(), uint(orgId), group.ID)
	if err != nil {
		a.writeAccessError(c, err, "reload renamed user group failed")
		return
	}
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.UserGroupResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data:    userGroupToAPI(view),
	})
}

// DeleteUserGroup removes a custom user group and reports cascaded rules.
func (a *AdminAPI) DeleteUserGroup(c *gin.Context, orgId int64, groupId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || groupId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermAccessManage) {
		return
	}
	cascaded, err := a.deps.Access.DeleteUserGroup(c.Request.Context(), uint(orgId), uid, uint(groupId))
	if err != nil {
		a.writeAccessError(c, err, "delete user group failed")
		return
	}
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.UserGroupDeleteResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data:    gen.UserGroupDeleteData{RemovedRules: cascaded},
	})
}

// ReplaceUserGroupMembers replaces the explicit member set of a custom group.
func (a *AdminAPI) ReplaceUserGroupMembers(c *gin.Context, orgId int64, groupId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || groupId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermAccessManage) {
		return
	}
	var req gen.UserGroupMembersRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid user group members body")
		return
	}
	// The contract marks user_ids required: a missing/null field must never be
	// read as "clear every member" (a typo would silently revoke access).
	if req.UserIds == nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "user_ids is required")
		return
	}
	ids := make([]uint, 0, len(req.UserIds))
	for _, id := range req.UserIds {
		if id <= 0 {
			abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid user id")
			return
		}
		ids = append(ids, uint(id))
	}
	removed, added, err := a.deps.Access.ReplaceUserGroupMembers(c.Request.Context(), uint(orgId), uid, uint(groupId), ids)
	if err != nil {
		a.writeAccessError(c, err, "replace user group members failed")
		return
	}
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.UserGroupMembersResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data:    gen.UserGroupMemberMutation{Added: added, Removed: removed},
	})
}

// writeAccessError maps access-control domain errors onto the contract codes.
func (a *AdminAPI) writeAccessError(c *gin.Context, err error, logMessage string) {
	switch {
	case errors.Is(err, access.ErrGroupNotFound):
		abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, "user group not found")
	case errors.Is(err, access.ErrDeviceGroupNotFound):
		abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, "device group not found")
	case errors.Is(err, access.ErrReservedGroup), errors.Is(err, access.ErrGroupNameTaken),
		errors.Is(err, access.ErrDeviceGroupNameTaken), errors.Is(err, access.ErrRuleExists):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "group conflict")
	case errors.Is(err, access.ErrInvalidGroupName), errors.Is(err, access.ErrInvalidMember),
		errors.Is(err, access.ErrInvalidDeviceGroupName), errors.Is(err, access.ErrInvalidDevice),
		errors.Is(err, access.ErrInvalidRule):
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid group request")
	case errors.Is(err, access.ErrRuleNotFound):
		abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, "access rule not found")
	case errors.Is(err, access.ErrAuditUnavailable):
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "audit unavailable")
	default:
		a.deps.Logger.Error(logMessage)
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "access operation failed")
	}
}

// deviceGroupToAPI maps one device group view onto the contract shape.
func deviceGroupToAPI(view access.DeviceGroupView) gen.DeviceGroup {
	ids := make([]int64, 0, len(view.DeviceIDs))
	for _, id := range view.DeviceIDs {
		ids = append(ids, int64(id))
	}
	return gen.DeviceGroup{
		Id:        int64(view.Group.ID),
		Name:      view.Group.Name,
		DeviceIds: ids,
		CreatedAt: view.Group.CreatedAt,
		UpdatedAt: view.Group.UpdatedAt,
	}
}

// ListDeviceGroups lists the organization's device groups.
func (a *AdminAPI) ListDeviceGroups(c *gin.Context, orgId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermAccessManage) {
		return
	}
	views, err := a.deps.Access.ListDeviceGroups(c.Request.Context(), uint(orgId))
	if err != nil {
		a.deps.Logger.Error("list device groups failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not list device groups")
		return
	}
	out := make([]gen.DeviceGroup, 0, len(views))
	for _, view := range views {
		out = append(out, deviceGroupToAPI(view))
	}
	c.JSON(http.StatusOK, gen.DeviceGroupListResponse{Code: gen.ErrorCodeOk, Message: "ok", Data: out})
}

// CreateDeviceGroup adds a device group.
func (a *AdminAPI) CreateDeviceGroup(c *gin.Context, orgId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermAccessManage) {
		return
	}
	var req gen.DeviceGroupCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid device group body")
		return
	}
	group, err := a.deps.Access.CreateDeviceGroup(c.Request.Context(), uint(orgId), uid, req.Name)
	if err != nil {
		a.writeAccessError(c, err, "create device group failed")
		return
	}
	view, err := a.deps.Access.DeviceGroupViewByID(c.Request.Context(), uint(orgId), group.ID)
	if err != nil {
		a.writeAccessError(c, err, "reload created device group failed")
		return
	}
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusCreated, gen.DeviceGroupResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data:    deviceGroupToAPI(view),
	})
}

// RenameDeviceGroup renames a device group.
func (a *AdminAPI) RenameDeviceGroup(c *gin.Context, orgId int64, deviceGroupId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || deviceGroupId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermAccessManage) {
		return
	}
	var req gen.DeviceGroupRenameRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid device group body")
		return
	}
	group, err := a.deps.Access.RenameDeviceGroup(c.Request.Context(), uint(orgId), uid, uint(deviceGroupId), req.Name)
	if err != nil {
		a.writeAccessError(c, err, "rename device group failed")
		return
	}
	view, err := a.deps.Access.DeviceGroupViewByID(c.Request.Context(), uint(orgId), group.ID)
	if err != nil {
		a.writeAccessError(c, err, "reload renamed device group failed")
		return
	}
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.DeviceGroupResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data:    deviceGroupToAPI(view),
	})
}

// DeleteDeviceGroup removes a device group and reports the cascade effects.
func (a *AdminAPI) DeleteDeviceGroup(c *gin.Context, orgId int64, deviceGroupId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || deviceGroupId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermAccessManage) {
		return
	}
	removedRules, ungrouped, err := a.deps.Access.DeleteDeviceGroup(c.Request.Context(), uint(orgId), uid, uint(deviceGroupId))
	if err != nil {
		a.writeAccessError(c, err, "delete device group failed")
		return
	}
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.DeviceGroupDeleteResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data: gen.DeviceGroupDeleteData{
			RemovedRules:     removedRules,
			UngroupedDevices: ungrouped,
		},
	})
}

// ReplaceDeviceGroupDevices replaces the device set of a group.
func (a *AdminAPI) ReplaceDeviceGroupDevices(c *gin.Context, orgId int64, deviceGroupId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || deviceGroupId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermAccessManage) {
		return
	}
	var req gen.DeviceGroupDevicesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid device group devices body")
		return
	}
	// device_ids is required: a missing field must not be read as "release every
	// device from the group".
	if req.DeviceIds == nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "device_ids is required")
		return
	}
	ids := make([]uint, 0, len(req.DeviceIds))
	for _, id := range req.DeviceIds {
		if id <= 0 {
			abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid device id")
			return
		}
		ids = append(ids, uint(id))
	}
	added, removed, err := a.deps.Access.ReplaceDeviceGroupDevices(c.Request.Context(), uint(orgId), uid, uint(deviceGroupId), ids)
	if err != nil {
		a.writeAccessError(c, err, "replace device group devices failed")
		return
	}
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.DeviceGroupDevicesResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data:    gen.DeviceGroupMemberMutation{Added: added, Removed: removed},
	})
}

// accessRuleToAPI maps one rule view onto the contract shape. all_devices rules
// carry a null target id and an empty target name.
func accessRuleToAPI(view access.RuleView) gen.AccessRule {
	var targetID *int64
	if view.Rule.TargetKind == model.AccessTargetKindDeviceGroup {
		id := int64(view.Rule.TargetGroupID)
		targetID = &id
	}
	return gen.AccessRule{
		Id:              int64(view.Rule.ID),
		SourceGroupId:   int64(view.Rule.SourceGroupID),
		SourceGroupName: view.SourceGroupName,
		TargetKind:      gen.AccessRuleTargetKind(view.Rule.TargetKind),
		TargetGroupId:   targetID,
		TargetGroupName: view.TargetGroupName,
		CreatedAt:       view.Rule.CreatedAt,
	}
}

// ListAccessRules lists the organization's allow rules.
func (a *AdminAPI) ListAccessRules(c *gin.Context, orgId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermAccessManage) {
		return
	}
	views, err := a.deps.Access.ListAccessRules(c.Request.Context(), uint(orgId))
	if err != nil {
		a.deps.Logger.Error("list access rules failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not list access rules")
		return
	}
	out := make([]gen.AccessRule, 0, len(views))
	for _, view := range views {
		out = append(out, accessRuleToAPI(view))
	}
	c.JSON(http.StatusOK, gen.AccessRuleListResponse{Code: gen.ErrorCodeOk, Message: "ok", Data: out})
}

// CreateAccessRule adds one allow rule.
func (a *AdminAPI) CreateAccessRule(c *gin.Context, orgId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermAccessManage) {
		return
	}
	var req gen.AccessRuleCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid access rule body")
		return
	}
	if req.SourceGroupId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid source group id")
		return
	}
	var targetGroupID uint
	if req.TargetGroupId != nil {
		if *req.TargetGroupId <= 0 {
			abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid target group id")
			return
		}
		targetGroupID = uint(*req.TargetGroupId)
	}
	rule, err := a.deps.Access.CreateAccessRule(c.Request.Context(), uint(orgId), uid,
		uint(req.SourceGroupId), string(req.TargetKind), targetGroupID)
	if err != nil {
		a.writeAccessError(c, err, "create access rule failed")
		return
	}
	// Reload through the list so the response carries the same names as GET.
	views, err := a.deps.Access.ListAccessRules(c.Request.Context(), uint(orgId))
	if err != nil {
		a.writeAccessError(c, err, "reload created access rule failed")
		return
	}
	for _, view := range views {
		if view.Rule.ID == rule.ID {
			c.Set(contextAuditRecorded, true)
			c.JSON(http.StatusCreated, gen.AccessRuleResponse{
				Code:    gen.ErrorCodeOk,
				Message: "ok",
				Data:    accessRuleToAPI(view),
			})
			return
		}
	}
	a.deps.Logger.Error("created access rule vanished")
	abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not load created access rule")
}

// DeleteAccessRule removes one rule.
func (a *AdminAPI) DeleteAccessRule(c *gin.Context, orgId int64, ruleId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || ruleId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermAccessManage) {
		return
	}
	if err := a.deps.Access.DeleteAccessRule(c.Request.Context(), uint(orgId), uid, uint(ruleId)); err != nil {
		a.writeAccessError(c, err, "delete access rule failed")
		return
	}
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.OkResponse{Code: gen.ErrorCodeOk, Message: "ok"})
}
