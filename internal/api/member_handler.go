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
// re-checks its permission. When lockOwners is set, the actor row and every
// owner row are locked in one id-ordered query, so concurrent owner removals
// acquire locks in the same order (no deadlock) and a lost actor is detected
// before any write or session revocation.
func lockActor(tx *gorm.DB, orgID, actorID uint, lockOwners bool, perm string) ([]model.Membership, error) {
	var rows []model.Membership
	read := store.ScopedByOrg(tx, orgID).Select("id", "user_id", "role")
	if lockOwners {
		read = read.Where("user_id = ? OR role = ?", actorID, model.RoleOwner)
	} else {
		read = read.Where("user_id = ?", actorID)
	}
	read = read.Order("id ASC")
	if tx.Name() != "sqlite" {
		read = read.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	if err := read.Find(&rows).Error; err != nil {
		return nil, err
	}

	var actor *model.Membership
	var owners []model.Membership
	for i := range rows {
		if rows[i].UserID == actorID {
			actor = &rows[i]
		}
		if rows[i].Role == model.RoleOwner {
			owners = append(owners, rows[i])
		}
	}
	if actor == nil || !authz.Can(actor.Role, perm) {
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
	if !authz.Can(actor.Role, authz.PermMemberManage) {
		abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden, "insufficient permissions")
		return
	}

	target, err := a.loadMembership(uint(orgId), uint(userId))
	if err != nil {
		a.writeMemberError(c, err, "could not load membership")
		return
	}
	if target.UserID == uid {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "cannot remove yourself")
		return
	}
	if target.Role == model.RoleOwner && actor.Role != model.RoleOwner {
		abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden, "only an owner can remove an owner")
		return
	}

	var revoked int64
	domainRecorded := false
	err = a.deps.DB.Transaction(func(tx *gorm.DB) error {
		owners, err := lockActor(tx, uint(orgId), uid, target.Role == model.RoleOwner, authz.PermMemberManage)
		if err != nil {
			return err
		}
		if target.Role == model.RoleOwner && len(owners) <= 1 {
			return errLastOwner
		}

		res := store.ScopedByOrg(tx, uint(orgId)).
			Where("user_id = ? AND role = ?", target.UserID, target.Role).Delete(&model.Membership{})
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
				Detail:         map[string]any{"role": target.Role, "revoked_sessions": n},
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
	actor, ok := a.membershipFor(c, uid, uint(orgId))
	if !ok {
		return
	}
	if !authz.Can(actor.Role, authz.PermOrgAdmin) {
		abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden, "only an owner can change roles")
		return
	}

	var req gen.MemberRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "role must be admin or member")
		return
	}
	role := string(req.Role)
	if role != model.RoleAdmin && role != model.RoleMember {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "role must be admin or member")
		return
	}

	target, err := a.loadMembership(uint(orgId), uint(userId))
	if err != nil {
		a.writeMemberError(c, err, "could not load membership")
		return
	}
	if target.UserID == uid {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "cannot change your own role")
		return
	}
	if target.Role == model.RoleOwner {
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "owner role changes are not supported")
		return
	}
	if target.Role == role {
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
			Where("user_id = ? AND role = ?", target.UserID, target.Role).Update("role", role)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return gorm.ErrRecordNotFound
		}

		if target.Role == model.RoleAdmin && role == model.RoleMember {
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
				Detail:         map[string]any{"from": target.Role, "to": role, "revoked_sessions": revoked},
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
	target.Role = role
	a.respondMember(c, target)
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
	c.JSON(http.StatusOK, gen.MemberResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data: gen.Member{
			Id:        int64(m.ID),
			UserId:    int64(m.UserID),
			Email:     types.Email(user.Email),
			Role:      gen.MemberRole(m.Role),
			CreatedAt: m.CreatedAt,
		},
	})
}
