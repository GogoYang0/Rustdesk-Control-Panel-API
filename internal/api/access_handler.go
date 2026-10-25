package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/access"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
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
	case errors.Is(err, access.ErrReservedGroup), errors.Is(err, access.ErrGroupNameTaken):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "user group conflict")
	case errors.Is(err, access.ErrInvalidGroupName), errors.Is(err, access.ErrInvalidMember):
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid user group request")
	case errors.Is(err, access.ErrAuditUnavailable):
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "audit unavailable")
	default:
		a.deps.Logger.Error(logMessage)
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "access operation failed")
	}
}
