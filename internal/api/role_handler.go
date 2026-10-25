package api

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// errAuditUnavailable refuses a sensitive role write when the configured
// auditor cannot record inside the same transaction. Returning 500 is the fail
// closed side of "no audit, no mutation".
var errAuditUnavailable = errors.New("transactional auditor unavailable")

// roleResponse maps a role row onto the wire shape.
func roleResponse(role *model.Role) gen.Role {
	return gen.Role{
		Id:          int64(role.ID),
		Name:        role.Name,
		Kind:        gen.RoleKind(role.Kind),
		Permissions: role.PermissionList(),
		AuditScope:  gen.RoleAuditScope(role.AuditScope),
		Builtin:     role.Builtin(),
		CreatedAt:   role.CreatedAt,
		UpdatedAt:   role.UpdatedAt,
	}
}

// ListPermissions serves the permission catalog. Every authenticated user may
// read it: clients build role editors from it.
func (a *AdminAPI) ListPermissions(c *gin.Context) {
	if _, ok := requireUserID(c); !ok {
		return
	}
	catalog := authz.Catalog()
	out := make([]gen.Permission, 0, len(catalog))
	for _, p := range catalog {
		out = append(out, gen.Permission{Code: p.Code, Description: p.Description, Delegable: p.Delegable})
	}
	c.JSON(http.StatusOK, gen.PermissionListResponse{Code: gen.ErrorCodeOk, Message: "ok", Data: out})
}

// ListRoles lists the builtin and custom roles of an organization.
func (a *AdminAPI) ListRoles(c *gin.Context, orgId int64) {
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
	roles, err := a.deps.Roles.List(uint(orgId))
	if err != nil {
		a.deps.Logger.Error("list roles failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not list roles")
		return
	}
	out := make([]gen.Role, 0, len(roles))
	for i := range roles {
		out = append(out, roleResponse(&roles[i]))
	}
	c.JSON(http.StatusOK, gen.RoleListResponse{Code: gen.ErrorCodeOk, Message: "ok", Data: out})
}

// GetRole returns one role of the organization.
func (a *AdminAPI) GetRole(c *gin.Context, orgId int64, roleId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || roleId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid id")
		return
	}
	if _, ok := a.membershipFor(c, uid, uint(orgId)); !ok {
		return
	}
	role, err := a.deps.Roles.RoleByID(uint(orgId), uint(roleId))
	if err != nil {
		a.writeRoleError(c, err, "load role failed")
		return
	}
	c.JSON(http.StatusOK, gen.RoleResponse{Code: gen.ErrorCodeOk, Message: "ok", Data: roleResponse(role)})
}

// CreateRole adds a custom role. Only an owner holds role.manage, and the
// audit entry commits with the row.
func (a *AdminAPI) CreateRole(c *gin.Context, orgId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermRoleManage) {
		return
	}
	var req gen.RoleCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid role body")
		return
	}
	scope := ""
	if req.AuditScope != nil {
		scope = string(*req.AuditScope)
	}

	var role *model.Role
	domainRecorded := false
	err := a.deps.DB.Transaction(func(tx *gorm.DB) error {
		if _, err := lockActor(tx, uint(orgId), uid, false, authz.PermRoleManage); err != nil {
			return err
		}
		created, err := a.deps.Roles.CreateCustomTx(tx, uint(orgId), req.Name, req.Permissions, scope)
		if err != nil {
			return err
		}
		role = created
		tr, ok := a.deps.Auditor.(audit.TxRecorder)
		if !ok {
			return errAuditUnavailable
		}
		if err := tr.RecordTx(tx, audit.Entry{
			OrganizationID: uint(orgId),
			ActorUserID:    uid,
			Action:         "role.create",
			TargetType:     "role",
			TargetID:       fmt.Sprint(created.ID),
			Detail:         map[string]any{"name": created.Name, "permissions": created.PermissionList(), "audit_scope": created.AuditScope},
		}); err != nil {
			return err
		}
		domainRecorded = true
		return nil
	})
	if err != nil {
		a.writeRoleError(c, err, "create role failed")
		return
	}
	a.markRoleRecorded(c, uint(orgId), domainRecorded)
	c.JSON(http.StatusCreated, gen.RoleResponse{Code: gen.ErrorCodeOk, Message: "ok", Data: roleResponse(role)})
}

// UpdateRole replaces a custom role's name, permission set and audit scope.
func (a *AdminAPI) UpdateRole(c *gin.Context, orgId int64, roleId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || roleId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermRoleManage) {
		return
	}
	var req gen.RoleUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid role body")
		return
	}
	scope := ""
	if req.AuditScope != nil {
		scope = string(*req.AuditScope)
	}

	var updated *model.Role
	domainRecorded := false
	err := a.deps.DB.Transaction(func(tx *gorm.DB) error {
		if _, err := lockActor(tx, uint(orgId), uid, false, authz.PermRoleManage); err != nil {
			return err
		}
		before, err := authz.RoleByIDTx(tx, uint(orgId), uint(roleId))
		if err != nil {
			return err
		}
		after, err := a.deps.Roles.UpdateCustomTx(tx, uint(orgId), uint(roleId), req.Name, req.Permissions, scope)
		if err != nil {
			return err
		}
		updated = after
		tr, ok := a.deps.Auditor.(audit.TxRecorder)
		if !ok {
			return errAuditUnavailable
		}
		if err := tr.RecordTx(tx, audit.Entry{
			OrganizationID: uint(orgId),
			ActorUserID:    uid,
			Action:         "role.update",
			TargetType:     "role",
			TargetID:       fmt.Sprint(after.ID),
			Detail: map[string]any{
				"from":        before.Name,
				"to":          after.Name,
				"permissions": after.PermissionList(),
				"audit_scope": after.AuditScope,
			},
		}); err != nil {
			return err
		}
		domainRecorded = true
		return nil
	})
	if err != nil {
		a.writeRoleError(c, err, "update role failed")
		return
	}
	a.markRoleRecorded(c, uint(orgId), domainRecorded)
	c.JSON(http.StatusOK, gen.RoleResponse{Code: gen.ErrorCodeOk, Message: "ok", Data: roleResponse(updated)})
}

// DeleteRole removes an unreferenced custom role.
func (a *AdminAPI) DeleteRole(c *gin.Context, orgId int64, roleId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || roleId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermRoleManage) {
		return
	}

	domainRecorded := false
	err := a.deps.DB.Transaction(func(tx *gorm.DB) error {
		if _, err := lockActor(tx, uint(orgId), uid, false, authz.PermRoleManage); err != nil {
			return err
		}
		before, err := authz.RoleByIDTx(tx, uint(orgId), uint(roleId))
		if err != nil {
			return err
		}
		if err := a.deps.Roles.DeleteCustomTx(tx, uint(orgId), uint(roleId)); err != nil {
			return err
		}
		tr, ok := a.deps.Auditor.(audit.TxRecorder)
		if !ok {
			return errAuditUnavailable
		}
		if err := tr.RecordTx(tx, audit.Entry{
			OrganizationID: uint(orgId),
			ActorUserID:    uid,
			Action:         "role.delete",
			TargetType:     "role",
			TargetID:       fmt.Sprint(before.ID),
			Detail:         map[string]any{"name": before.Name, "permissions": before.PermissionList(), "audit_scope": before.AuditScope},
		}); err != nil {
			return err
		}
		domainRecorded = true
		return nil
	})
	if err != nil {
		a.writeRoleError(c, err, "delete role failed")
		return
	}
	a.markRoleRecorded(c, uint(orgId), domainRecorded)
	c.JSON(http.StatusOK, gen.OkResponse{Code: gen.ErrorCodeOk, Message: "ok"})
}

// markRoleRecorded tells the audit middleware whether the mutation already
// wrote its entry; otherwise the request-scoped fallback records it.
func (a *AdminAPI) markRoleRecorded(c *gin.Context, orgID uint, recorded bool) {
	if recorded {
		c.Set(contextAuditRecorded, true)
		return
	}
	c.Set(contextOrgID, orgID)
}

// writeRoleError maps role service sentinels onto HTTP responses.
func (a *AdminAPI) writeRoleError(c *gin.Context, err error, logMsg string) {
	switch {
	case errors.Is(err, authz.ErrRoleNotFound):
		abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, "role not found")
	case errors.Is(err, authz.ErrRoleBuiltin):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "builtin roles cannot be modified")
	case errors.Is(err, authz.ErrRoleNameTaken):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "role name is already in use")
	case errors.Is(err, authz.ErrRoleInUse):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "role is still assigned to members")
	case errors.Is(err, authz.ErrPermissionNotDelegable):
		abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden, "permission is not delegable")
	case errors.Is(err, authz.ErrUnknownPermission),
		errors.Is(err, authz.ErrInvalidRoleName),
		errors.Is(err, authz.ErrInvalidAuditScope):
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, err.Error())
	case errors.Is(err, errActorNoLongerAuthorized):
		abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden, "insufficient permissions")
	case errors.Is(err, errAuditUnavailable):
		a.deps.Logger.Error(logMsg + ": transactional auditor unavailable")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "audit unavailable")
	default:
		a.deps.Logger.Error(logMsg)
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not apply role change")
	}
}
