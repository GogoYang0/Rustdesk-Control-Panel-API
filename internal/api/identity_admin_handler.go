package api

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
	"gorm.io/gorm/clause"
)

// errIdentityResetLockout refuses a reset that would leave the account with no
// working credential at all.
var errIdentityResetLockout = errors.New("target has no local credential and a working binding")

// ResetMemberIdentity clears a member's external bindings. The authorization
// chain is the shared factor-reset chain (self, owner, cross-org), plus the
// lockout rule from design O14: an account with no local credential and a
// working binding would be locked out — but a fully conflicted binding set is
// already unusable, so resetting it is the repair path, not the damage.
func (a *AdminAPI) ResetMemberIdentity(c *gin.Context, orgId int64, userId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || userId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermMemberManage) {
		return
	}
	if uint(userId) == uid {
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "cannot reset your own identities")
		return
	}
	if _, err := a.loadMembership(uint(orgId), uint(userId)); err != nil {
		a.writeMemberError(c, err, "could not load membership")
		return
	}

	orgID, targetID := uint(orgId), uint(userId)
	err := a.deps.DB.Transaction(func(tx *gorm.DB) error {
		if err := a.assertResettableFactor(tx, c, orgID, targetID); err != nil {
			return err
		}
		// Lock the account row so concurrent credential removals (password,
		// passkeys, identities) serialize on the same lock.
		read := tx
		if tx.Name() != "sqlite" {
			read = read.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		var target model.User
		if err := store.WithoutTenantScope(read).Where("id = ?", targetID).First(&target).Error; err != nil {
			return err
		}
		var passkeys int64
		if err := tx.Model(&model.UserPasskey{}).Where("user_id = ?", targetID).Count(&passkeys).Error; err != nil {
			return err
		}
		var working int64
		if err := tx.Model(&model.UserIdentity{}).
			Where("user_id = ? AND conflict_at IS NULL", targetID).Count(&working).Error; err != nil {
			return err
		}
		hadLocal := auth.HasPassword(target) || passkeys > 0
		if !hadLocal && working > 0 {
			return errIdentityResetLockout
		}
		// The O14 exception is judged on conflict_at; recording it lets an
		// operator tell a repair (everything conflicted) from a lockout risk
		// when reading the audit trail later.
		var conflicted int64
		if err := tx.Model(&model.UserIdentity{}).
			Where("user_id = ? AND conflict_at IS NOT NULL", targetID).Count(&conflicted).Error; err != nil {
			return err
		}

		res := tx.Where("user_id = ?", targetID).Delete(&model.UserIdentity{})
		if res.Error != nil {
			return res.Error
		}
		recorder, ok := a.deps.Auditor.(audit.TxRecorder)
		if !ok {
			return errAuditUnavailable
		}
		return recorder.RecordTx(tx, audit.Entry{
			OrganizationID: orgID,
			ActorUserID:    uid,
			Action:         "user.identity.reset",
			TargetType:     "user",
			TargetID:       fmt.Sprint(targetID),
			Detail: map[string]any{
				"removed":              res.RowsAffected,
				"had_local_credential": hadLocal,
				"conflict_at":          conflicted > 0,
			},
		})
	})

	switch {
	case errors.Is(err, errIdentityResetLockout):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict,
			"target has no local credential; resetting a working binding would lock the account")
		return
	case errors.Is(err, errFactorOwnerReset):
		abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden, "only an owner can reset an owner's identities")
		return
	case errors.Is(err, errFactorOtherOrgMembership):
		abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden,
			"target also belongs to another organization; account-wide recovery must be handled out of band")
		return
	case errors.Is(err, errAuditUnavailable):
		a.deps.Logger.Error("reset identities failed: transactional auditor unavailable")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "audit unavailable")
		return
	case err != nil:
		a.deps.Logger.Error("reset identities failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not reset identities")
		return
	}

	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.OkResponse{Code: gen.ErrorCodeOk, Message: "ok"})
}
