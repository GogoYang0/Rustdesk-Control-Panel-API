package api

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/oapi-codegen/runtime/types"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/compatapi"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// errLastOwner reports a removal that would leave the organization without an
// owner.
var errLastOwner = errors.New("organization must keep at least one owner")

// errActorNoLongerAuthorized reports an actor whose membership disappeared or
// whose role no longer grants the operation between the handler check and the
// transaction: the stale permission must not be allowed to mutate the org.
var errActorNoLongerAuthorized = errors.New("actor is no longer authorized")

// lockActor re-reads the actor membership inside the mutation transaction and
// re-checks its permission set. When lockOwners is set, the actor row and every
// owner row are locked in one id-ordered query, so concurrent owner removals
// acquire locks in the same order (no deadlock) and a lost actor is detected
// before any write or session revocation. Owner rows are identified by the role
// kind, never by the legacy role string.
func lockActor(tx *gorm.DB, orgID, actorID uint, lockOwners bool, required ...string) ([]model.Membership, error) {
	var rows []model.Membership
	// No JOIN here: the tenant plugin injects an unqualified organization_id
	// condition, which becomes ambiguous once two scoped tables are joined.
	// Owner rows are resolved from the role rows below instead.
	read := store.ScopedByOrg(tx, orgID).Model(&model.Membership{})
	if !lockOwners {
		read = read.Where("user_id = ?", actorID)
	}
	read = read.Order("id ASC")
	if tx.Name() != "sqlite" {
		read = read.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	if err := read.Find(&rows).Error; err != nil {
		return nil, err
	}

	var roles []model.Role
	if err := store.ScopedByOrg(tx, orgID).Find(&roles).Error; err != nil {
		return nil, err
	}
	kinds := make(map[uint]string, len(roles))
	rolePerms := make(map[uint][]string, len(roles))
	for _, r := range roles {
		kinds[r.ID] = r.Kind
		rolePerms[r.ID] = r.PermissionList()
	}

	var actor *model.Membership
	var owners []model.Membership
	for i := range rows {
		if rows[i].UserID == actorID {
			actor = &rows[i]
		}
		// Only active owners count: disabling every active owner would leave the
		// organization unadministrable, and removing a disabled one is harmless
		// while another active owner remains.
		if kinds[rows[i].RoleID] == model.RoleKindOwner && !rows[i].Disabled {
			owners = append(owners, rows[i])
		}
	}
	if actor == nil || actor.Disabled {
		return nil, errActorNoLongerAuthorized
	}
	for _, perm := range required {
		if !authz.Has(rolePerms[actor.RoleID], perm) {
			return nil, errActorNoLongerAuthorized
		}
	}
	return owners, nil
}

// RemoveMember removes a membership and revokes the user's compat sessions in
// the same transaction (#39): an offboarded member must not keep a 720h token
// that can still drive devices or read the address book. A revocation failure
// rolls the removal back, so the caller never sees a success the server did
// not fully apply.
func (a *AdminAPI) RemoveMember(c *gin.Context, orgId int64, userId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || userId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid id")
		return
	}
	actor, ok := a.membershipFor(c, uid, uint(orgId))
	if !ok {
		return
	}
	if perms, _ := authz.OrgPermissions(c); !authz.Has(perms, authz.PermMemberManage) {
		abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden, "insufficient permissions")
		return
	}

	target, err := a.loadMembership(uint(orgId), uint(userId))
	if err != nil {
		a.writeMemberError(c, err, "could not load membership")
		return
	}
	roleIdx, err := a.roleIndex(uint(orgId))
	if err != nil {
		a.deps.Logger.Error("load roles failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not load role")
		return
	}
	actorKind := roleKindOf(roleIdx, actor.RoleID)
	targetKind := roleKindOf(roleIdx, target.RoleID)
	if target.UserID == uid {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "cannot remove yourself")
		return
	}
	if targetKind == model.RoleKindOwner && actorKind != model.RoleKindOwner {
		abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden, "only an owner can remove an owner")
		return
	}

	var revoked int64
	domainRecorded := false
	err = a.deps.DB.Transaction(func(tx *gorm.DB) error {
		owners, err := lockActor(tx, uint(orgId), uid, targetKind == model.RoleKindOwner, authz.PermMemberManage)
		if err != nil {
			return err
		}
		if targetKind == model.RoleKindOwner {
			// Count the owners that remain after removing the target. A disabled
			// co-owner is already excluded from the active set, so removing them
			// must not trip this guard while the actor stays an active owner.
			remaining := 0
			for _, owner := range owners {
				if owner.UserID != target.UserID {
					remaining++
				}
			}
			if remaining == 0 {
				return errLastOwner
			}
		}

		res := store.ScopedByOrg(tx, uint(orgId)).
			Where("user_id = ? AND role_id = ?", target.UserID, target.RoleID).Delete(&model.Membership{})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return gorm.ErrRecordNotFound
		}

		// Group membership is derived from organization membership: the group
		// rows must go with the membership, or re-inviting the user would
		// silently restore every old group's access.
		if err := store.ScopedByOrg(tx, uint(orgId)).
			Where("user_id = ?", target.UserID).
			Delete(&model.UserGroupMember{}).Error; err != nil {
			return err
		}

		n, err := compatapi.RevokeOrgSessions(c.Request.Context(), tx, uint(orgId), target.UserID, a.deps.Now())
		if err != nil {
			return fmt.Errorf("revoke compat sessions: %w", err)
		}
		revoked = n

		if tr, ok := a.deps.Auditor.(audit.TxRecorder); !ok {
			return errAuditUnavailable
		} else if err := tr.RecordTx(tx, audit.Entry{
			OrganizationID: uint(orgId),
			ActorUserID:    uid,
			Action:         "organization.member.remove",
			TargetType:     "user",
			TargetID:       fmt.Sprint(target.UserID),
			Detail:         map[string]any{"role": roleNameOf(roleIdx, target.RoleID), "revoked_sessions": n},
		}); err != nil {
			return err
		}
		domainRecorded = true
		return nil
	})
	switch {
	case errors.Is(err, errActorNoLongerAuthorized):
		abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden, "insufficient permissions")
		return
	case errors.Is(err, errAuditUnavailable):
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "audit unavailable")
		return
	case errors.Is(err, errLastOwner):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "organization must keep at least one owner")
		return
	case errors.Is(err, gorm.ErrRecordNotFound):
		abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, "member not found")
		return
	case err != nil:
		a.deps.Logger.Error("remove member failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not remove member")
		return
	}

	if domainRecorded {
		c.Set(contextAuditRecorded, true)
	} else {
		c.Set(contextOrgID, uint(orgId))
	}
	c.JSON(http.StatusOK, gen.MemberMutationResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data:    gen.MemberMutation{RevokedSessions: revoked},
	})
}

// UpdateMemberRole updates a membership by field. role_id grants a builtin
// admin/member role or a custom role (owner-only, org.admin); disabled stops or
// restores the membership (member.manage). Both may be sent together and each
// needs its own permission. Ownership transfer is out of scope, so the owner
// role can never be granted here, and the last owner can never be disabled.
//
// A change that takes permissions away — a narrowing role change or a disable —
// revokes the user's compat sessions in the same transaction: a capability that
// was withdrawn must not keep a 720h token that still authorizes it.
func (a *AdminAPI) UpdateMemberRole(c *gin.Context, orgId int64, userId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || userId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid id")
		return
	}
	if _, ok := a.membershipFor(c, uid, uint(orgId)); !ok {
		return
	}

	var req gen.MemberUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid member update")
		return
	}
	if req.RoleId == nil && req.Disabled == nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "at least one of role_id or disabled is required")
		return
	}
	perms, _ := authz.OrgPermissions(c)
	if req.RoleId != nil && !authz.Has(perms, authz.PermOrgAdmin) {
		abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden, "only an owner can change roles")
		return
	}
	if req.Disabled != nil && !authz.Has(perms, authz.PermMemberManage) {
		abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden, "insufficient permissions")
		return
	}

	target, err := a.loadMembership(uint(orgId), uint(userId))
	if err != nil {
		a.writeMemberError(c, err, "could not load membership")
		return
	}
	roleIdx, err := a.roleIndex(uint(orgId))
	if err != nil {
		a.deps.Logger.Error("load roles failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not load role")
		return
	}
	targetKind := roleKindOf(roleIdx, target.RoleID)

	// Resolve the role change, if any.
	var newRole *model.Role
	if req.RoleId != nil {
		if target.UserID == uid {
			abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "cannot change your own role")
			return
		}
		if targetKind == model.RoleKindOwner {
			abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "owner role changes are not supported")
			return
		}
		role, err := a.deps.Roles.RoleByID(uint(orgId), uint(*req.RoleId))
		if err != nil {
			a.writeRoleError(c, err, "load target role failed")
			return
		}
		if role.Kind == model.RoleKindOwner {
			abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden, "owner role cannot be granted")
			return
		}
		if target.RoleID != role.ID {
			newRole = role
		}
	}

	// Resolve the disable change, if any. Repeating the current state is a
	// successful no-op instead of a second audit row.
	var disableTo *bool
	if req.Disabled != nil {
		if *req.Disabled && target.UserID == uid {
			abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "cannot disable yourself")
			return
		}
		if targetKind == model.RoleKindOwner && !authz.Has(perms, authz.PermOrgAdmin) {
			abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden, "only an owner can change an owner's membership")
			return
		}
		if target.Disabled != *req.Disabled {
			disableTo = req.Disabled
		}
	}

	if newRole == nil && disableTo == nil {
		a.respondMember(c, target)
		return
	}

	oldRole, oldKnown := roleIdx[target.RoleID]
	if newRole != nil && !oldKnown {
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "membership role unavailable")
		return
	}
	narrowed := false
	if newRole != nil {
		for _, p := range oldRole.PermissionList() {
			if !authz.Has(newRole.PermissionList(), p) {
				narrowed = true
				break
			}
		}
	}
	revoke := narrowed || (disableTo != nil && *disableTo)

	var revoked int64
	domainRecorded := false
	err = a.deps.DB.Transaction(func(tx *gorm.DB) error {
		var required []string
		if newRole != nil {
			required = append(required, authz.PermOrgAdmin)
		}
		if disableTo != nil {
			required = append(required, authz.PermMemberManage)
		}
		owners, err := lockActor(tx, uint(orgId), uid, disableTo != nil && *disableTo && targetKind == model.RoleKindOwner, required...)
		if err != nil {
			return err
		}
		if disableTo != nil && *disableTo && targetKind == model.RoleKindOwner && len(owners) <= 1 {
			return errLastOwner
		}

		updates := map[string]any{}
		if newRole != nil {
			updates["role_id"] = newRole.ID
		}
		if disableTo != nil {
			updates["disabled"] = *disableTo
			if *disableTo {
				now := a.deps.Now()
				updates["disabled_at"] = now
				updates["disabled_by"] = uid
			} else {
				updates["disabled_at"] = nil
				updates["disabled_by"] = uint(0)
			}
		}
		res := store.ScopedByOrg(tx, uint(orgId)).Model(&model.Membership{}).
			Where("user_id = ? AND role_id = ?", target.UserID, target.RoleID).
			Updates(updates)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return gorm.ErrRecordNotFound
		}

		if revoke {
			n, err := compatapi.RevokeOrgSessions(c.Request.Context(), tx, uint(orgId), target.UserID, a.deps.Now())
			if err != nil {
				return fmt.Errorf("revoke compat sessions: %w", err)
			}
			revoked = n
		}

		tr, ok := a.deps.Auditor.(audit.TxRecorder)
		if !ok {
			return errAuditUnavailable
		}
		if newRole != nil {
			if err := tr.RecordTx(tx, audit.Entry{
				OrganizationID: uint(orgId),
				ActorUserID:    uid,
				Action:         "organization.member.role",
				TargetType:     "user",
				TargetID:       fmt.Sprint(target.UserID),
				Detail:         map[string]any{"from": oldRole.Name, "to": newRole.Name, "revoked_sessions": revoked},
			}); err != nil {
				return err
			}
		}
		if disableTo != nil {
			action := "organization.member.enable"
			if *disableTo {
				action = "organization.member.disable"
			}
			if err := tr.RecordTx(tx, audit.Entry{
				OrganizationID: uint(orgId),
				ActorUserID:    uid,
				Action:         action,
				TargetType:     "user",
				TargetID:       fmt.Sprint(target.UserID),
				Detail:         map[string]any{"revoked_sessions": revoked},
			}); err != nil {
				return err
			}
		}
		domainRecorded = true
		return nil
	})
	switch {
	case errors.Is(err, errActorNoLongerAuthorized):
		abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden, "insufficient permissions")
		return
	case errors.Is(err, errAuditUnavailable):
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "audit unavailable")
		return
	case errors.Is(err, errLastOwner):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "organization must keep at least one owner")
		return
	case errors.Is(err, gorm.ErrRecordNotFound):
		abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, "member not found")
		return
	case err != nil:
		a.deps.Logger.Error("update member failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not update member")
		return
	}

	if domainRecorded {
		c.Set(contextAuditRecorded, true)
	} else {
		c.Set(contextOrgID, uint(orgId))
	}
	if newRole != nil {
		target.RoleID = newRole.ID
	}
	if disableTo != nil {
		target.Disabled = *disableTo
	}
	a.respondMember(c, target)
}

// roleIndex loads the tenant's roles keyed by id. Member responses and owner
// checks read names and kinds from this index, never from the legacy string.
func (a *AdminAPI) roleIndex(orgID uint) (map[uint]model.Role, error) {
	var roles []model.Role
	if err := store.ScopedByOrg(a.deps.DB, orgID).Find(&roles).Error; err != nil {
		return nil, err
	}
	out := make(map[uint]model.Role, len(roles))
	for _, r := range roles {
		out[r.ID] = r
	}
	return out, nil
}

// roleKindOf returns the kind of a role id, or "" when it is unknown.
func roleKindOf(idx map[uint]model.Role, roleID uint) string {
	if r, ok := idx[roleID]; ok {
		return r.Kind
	}
	return ""
}

// roleNameOf returns the display name of a role id, or "" when it is unknown.
func roleNameOf(idx map[uint]model.Role, roleID uint) string {
	if r, ok := idx[roleID]; ok {
		return r.Name
	}
	return ""
}

// loadMembership reads a membership by (org, user) cross-tenant, because the
// caller may address a user in an organization the lookup itself must scope.
func (a *AdminAPI) loadMembership(orgID, userID uint) (*model.Membership, error) {
	var m model.Membership
	err := store.WithoutTenantScope(a.deps.DB).
		Where("organization_id = ? AND user_id = ?", orgID, userID).
		First(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	return &m, nil
}

func (a *AdminAPI) writeMemberError(c *gin.Context, err error, logMsg string) {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, "member not found")
		return
	}
	a.deps.Logger.Error(logMsg)
	abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not load membership")
}

// respondMember returns the membership with the user's email, the shape the
// member listing uses.
func (a *AdminAPI) respondMember(c *gin.Context, m *model.Membership) {
	var user model.User
	if err := store.WithoutTenantScope(a.deps.DB).First(&user, m.UserID).Error; err != nil {
		a.deps.Logger.Error("load member user failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not load member")
		return
	}
	// The role row is the only source; a missing row leaves the name empty
	// instead of guessing from the legacy string (fail closed).
	name := ""
	if role, err := a.deps.Roles.RoleByID(m.OrganizationID, m.RoleID); err == nil {
		name = role.Name
	}
	c.JSON(http.StatusOK, gen.MemberResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data: gen.Member{
			Id:       int64(m.ID),
			UserId:   int64(m.UserID),
			Email:    types.Email(user.Email),
			Role:     name,
			RoleId:   int64(m.RoleID),
			RoleName: name,
			// Read-back for the console: without it the page can assign roles
			// but never shows who holds which.
			ControlRoleId: controlRoleIDOf(*m),
			StrategyId:    strategyIDToAPI(m.StrategyID),
			Disabled:      m.Disabled,
			CreatedAt:     m.CreatedAt,
		},
	})
}
