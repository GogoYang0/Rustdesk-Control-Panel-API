package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/controlrole"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// controlRoleResponse maps a stored role onto the wire shape. Permissions are
// decoded from the stored JSON; an unreadable payload degrades to the
// all-use_client default rather than failing the list request.
func controlRoleResponse(role *model.ControlRole) gen.ControlRole {
	perms := controlrole.DefaultPermissions()
	if err := json.Unmarshal([]byte(role.PermissionsJSON), &perms); err != nil {
		perms = controlrole.DefaultPermissions()
	}
	return gen.ControlRole{
		Id:          int64(role.ID),
		Name:        role.Name,
		Kind:        gen.ControlRoleKind(role.Kind),
		Permissions: controlPermissionsToWire(perms),
		Builtin:     role.Kind == model.KindControlRoleDefault,
		CreatedAt:   role.CreatedAt,
		UpdatedAt:   role.UpdatedAt,
	}
}

func controlPermissionsToWire(p controlrole.Permissions) gen.ControlPermissionStates {
	out := make(gen.ControlPermissionStates, len(p))
	for k, v := range p {
		out[k] = gen.ControlPermissionState(v)
	}
	return out
}

func controlPermissionsFromWire(p gen.ControlPermissionStates) controlrole.Permissions {
	out := make(controlrole.Permissions, len(p))
	for k, v := range p {
		out[k] = controlrole.State(v)
	}
	return out
}

// writeControlRoleError maps control role sentinels onto HTTP responses.
func (a *AdminAPI) writeControlRoleError(c *gin.Context, err error, logMsg string) {
	switch {
	case errors.Is(err, controlrole.ErrNotFound):
		abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, "control role not found")
	case errors.Is(err, controlrole.ErrBuiltinImmutable):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "the built-in default role cannot be renamed or deleted")
	case errors.Is(err, controlrole.ErrDuplicateName):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "control role name is already in use")
	case errors.Is(err, controlrole.ErrInvalidName),
		errors.Is(err, controlrole.ErrUnknownPermissionKey),
		errors.Is(err, controlrole.ErrInvalidPermissionState):
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, err.Error())
	case errors.Is(err, controlrole.ErrUnaudited):
		a.deps.Logger.Error(logMsg + ": transactional auditor unavailable")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "audit unavailable")
	default:
		a.deps.Logger.Error(logMsg)
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not apply control role change")
	}
}

// ListControlRoles returns the organization's control roles. Any member may
// read them: the console needs the list to render assignments.
func (a *AdminAPI) ListControlRoles(c *gin.Context, orgId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization id")
		return
	}
	if _, ok := a.membershipFor(c, uid, uint(orgId)); !ok {
		return
	}
	roles, err := a.deps.ControlRoles.List(c.Request.Context(), uint(orgId))
	if err != nil {
		a.deps.Logger.Error("list control roles failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not list control roles")
		return
	}
	out := make([]gen.ControlRole, 0, len(roles))
	for i := range roles {
		out = append(out, controlRoleResponse(&roles[i]))
	}
	c.JSON(http.StatusOK, gen.ControlRoleListResponse{Code: gen.ErrorCodeOk, Message: "ok", Data: out})
}

// CreateControlRole adds a custom role.
func (a *AdminAPI) CreateControlRole(c *gin.Context, orgId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermControlRoleManage) {
		return
	}
	var req gen.ControlRoleCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid control role body")
		return
	}
	role, err := a.deps.ControlRoles.Create(c.Request.Context(), uint(orgId), uid, req.Name,
		controlPermissionsFromWire(req.Permissions))
	if err != nil {
		a.writeControlRoleError(c, err, "create control role failed")
		return
	}
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusCreated, gen.ControlRoleResponse{Code: gen.ErrorCodeOk, Message: "ok", Data: controlRoleResponse(role)})
}

// UpdateControlRole changes a role's name and/or permissions.
func (a *AdminAPI) UpdateControlRole(c *gin.Context, orgId int64, roleId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || roleId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermControlRoleManage) {
		return
	}
	var req gen.ControlRoleUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid control role body")
		return
	}
	if req.Name == nil && req.Permissions == nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "at least one of name or permissions is required")
		return
	}
	var perms *controlrole.Permissions
	if req.Permissions != nil {
		converted := controlPermissionsFromWire(*req.Permissions)
		perms = &converted
	}
	role, err := a.deps.ControlRoles.Update(c.Request.Context(), uint(orgId), uid, uint(roleId), req.Name, perms)
	if err != nil {
		a.writeControlRoleError(c, err, "update control role failed")
		return
	}
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.ControlRoleResponse{Code: gen.ErrorCodeOk, Message: "ok", Data: controlRoleResponse(role)})
}

// DeleteControlRole removes a custom role and clears its assignments.
func (a *AdminAPI) DeleteControlRole(c *gin.Context, orgId int64, roleId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || roleId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermControlRoleManage) {
		return
	}
	if err := a.deps.ControlRoles.Delete(c.Request.Context(), uint(orgId), uid, uint(roleId)); err != nil {
		a.writeControlRoleError(c, err, "delete control role failed")
		return
	}
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.OkResponse{Code: gen.ErrorCodeOk, Message: "ok"})
}

// AssignMemberControlRole sets or clears one member's control role. A null
// control_role_id means "back to the organization default".
func (a *AdminAPI) AssignMemberControlRole(c *gin.Context, orgId int64, userId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || userId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermControlRoleManage) {
		return
	}
	var req gen.ControlRoleAssignmentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid control role assignment")
		return
	}
	var roleID *uint
	if req.ControlRoleId != nil {
		if *req.ControlRoleId <= 0 {
			abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "control_role_id must be positive or null")
			return
		}
		id := uint(*req.ControlRoleId)
		roleID = &id
	}
	if err := a.deps.ControlRoles.Assign(c.Request.Context(), uint(orgId), uid, uint(userId), roleID); err != nil {
		a.writeControlRoleError(c, err, "assign control role failed")
		return
	}
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.OkResponse{Code: gen.ErrorCodeOk, Message: "ok"})
}
