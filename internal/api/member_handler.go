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
func lockActor(tx *gorm.DB, orgID, actorID uint, lockOwners bool, perm string) ([]model.Membership, error) {
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
	perms := make(map[uint][]string, len(roles))
	for _, r := range roles {
		kinds[r.ID] = r.Kind
		perms[r.ID] = r.PermissionList()
	}

	var actor *model.Membership
	var owners []model.Membership
	for i := range rows {
		if rows[i].UserID == actorID {
			actor = &rows[i]
		}
		if kinds[rows[i].RoleID] == model.RoleKindOwner {
			owners = append(owners, rows[i])
		}
	}
	if actor == nil || !authz.Has(perms[actor.RoleID], perm) {
		return nil, errActorNoLongerAuthorized
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
		if targetKind == model.RoleKindOwner && len(owners) <= 1 {
			return errLastOwner
		}

		res := store.ScopedByOrg(tx, uint(orgId)).
			Where("user_id = ? AND role_id = ?", target.UserID, target.RoleID).Delete(&model.Membership{})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return gorm.ErrRecordNotFound
		}

		n, err := compatapi.RevokeOrgSessions(c.Request.Context(), tx, uint(orgId), target.UserID, a.deps.Now())
		if err != nil {
			return fmt.Errorf("revoke compat sessions: %w", err)
		}
		revoked = n

		if tr, ok := a.deps.Auditor.(audit.TxRecorder); ok {
			if err := tr.RecordTx(tx, audit.Entry{
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
		}
		return nil
	})
	switch {
	case errors.Is(err, errActorNoLongerAuthorized):
		abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden, "insufficient permissions")
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

// UpdateMemberRole changes a membership between admin and member. Only an
// owner may do this; ownership transfer is out of scope. A demotion revokes the
// user's compat sessions in the same transaction — the member lost the role
// that justified those sessions, and #39 treats that as an offboarding event.
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
	if perms, _ := authz.OrgPermissions(c); !authz.Has(perms, authz.PermOrgAdmin) {
		abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden, "only an owner can change roles")
		return
	}

	var req gen.MemberRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "role must be admin or member")
		return
	}
	roleName := string(req.Role)
	if roleName != model.RoleAdmin && roleName != model.RoleMember {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "role must be admin or member")
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
	if target.UserID == uid {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "cannot change your own role")
		return
	}
	if targetKind == model.RoleKindOwner {
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "owner role changes are not supported")
		return
	}
	newRole := roleByName(roleIdx, roleName)
	if newRole == nil {
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "role not seeded")
		return
	}
	if target.RoleID == newRole.ID {
		a.respondMember(c, target)
		return
	}

	var revoked int64
	domainRecorded := false
	err = a.deps.DB.Transaction(func(tx *gorm.DB) error {
		if _, err := lockActor(tx, uint(orgId), uid, false, authz.PermOrgAdmin); err != nil {
			return err
		}
		res := store.ScopedByOrg(tx, uint(orgId)).Model(&model.Membership{}).
			Where("user_id = ? AND role_id = ?", target.UserID, target.RoleID).
			Updates(map[string]any{"role_id": newRole.ID, "role": newRole.Name})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return gorm.ErrRecordNotFound
		}

		if targetKind == model.RoleKindAdmin && newRole.Kind == model.RoleKindMember {
			n, err := compatapi.RevokeOrgSessions(c.Request.Context(), tx, uint(orgId), target.UserID, a.deps.Now())
			if err != nil {
				return fmt.Errorf("revoke compat sessions: %w", err)
			}
			revoked = n
		}

		if tr, ok := a.deps.Auditor.(audit.TxRecorder); ok {
			if err := tr.RecordTx(tx, audit.Entry{
				OrganizationID: uint(orgId),
				ActorUserID:    uid,
				Action:         "organization.member.role",
				TargetType:     "user",
				TargetID:       fmt.Sprint(target.UserID),
				Detail:         map[string]any{"from": roleNameOf(roleIdx, target.RoleID), "to": newRole.Name, "revoked_sessions": revoked},
			}); err != nil {
				return err
			}
			domainRecorded = true
		}
		return nil
	})
	switch {
	case errors.Is(err, errActorNoLongerAuthorized):
		abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden, "insufficient permissions")
		return
	case errors.Is(err, gorm.ErrRecordNotFound):
		abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, "member not found")
		return
	case err != nil:
		a.deps.Logger.Error("update member role failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not update member role")
		return
	}

	if domainRecorded {
		c.Set(contextAuditRecorded, true)
	} else {
		c.Set(contextOrgID, uint(orgId))
	}
	target.RoleID = newRole.ID
	target.Role = newRole.Name
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

// roleByName returns a copy of the role with that name, or nil.
func roleByName(idx map[uint]model.Role, name string) *model.Role {
	for _, r := range idx {
		if r.Name == name {
			role := r
			return &role
		}
	}
	return nil
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
	name := m.Role
	if role, err := a.deps.Roles.RoleByID(m.OrganizationID, m.RoleID); err == nil {
		name = role.Name
	}
	c.JSON(http.StatusOK, gen.MemberResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data: gen.Member{
			Id:        int64(m.ID),
			UserId:    int64(m.UserID),
			Email:     types.Email(user.Email),
			Role:      gen.MemberRole(name),
			CreatedAt: m.CreatedAt,
		},
	})
}
