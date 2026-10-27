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
)

var errPasskeyResetLockout = errors.New("target has no password; resetting passkeys would lock the account")

// ResetMemberPasskeys clears a member's credentials. The authorization chain is
// the same one that guards the TOTP reset, plus a lockout check: an account
// without a password cannot survive losing its last passkey.
func (a *AdminAPI) ResetMemberPasskeys(c *gin.Context, orgId int64, userId int64) {
	if _, ok := a.passkeysEnabled(c); !ok {
		return
	}
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
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "cannot reset your own passkeys")
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
		var target model.User
		if err := store.WithoutTenantScope(tx).Where("id = ?", targetID).First(&target).Error; err != nil {
			return err
		}
		if !auth.HasPassword(target) {
			return errPasskeyResetLockout
		}
		res := tx.Where("user_id = ?", targetID).Delete(&model.UserPasskey{})
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
			Action:         "user.passkey.reset",
			TargetType:     "user",
			TargetID:       fmt.Sprint(targetID),
			Detail: map[string]any{
				"had_configuration": res.RowsAffected > 0,
				"removed":           res.RowsAffected,
			},
		})
	})

	switch {
	case errors.Is(err, errPasskeyResetLockout):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict,
			"target has no password; resetting its passkeys would lock the account")
		return
	case errors.Is(err, errFactorOwnerReset):
		abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden, "only an owner can reset an owner's passkeys")
		return
	case errors.Is(err, errFactorOtherOrgMembership):
		abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden,
			"target also belongs to another organization; account-wide recovery must be handled out of band")
		return
	case errors.Is(err, errAuditUnavailable):
		a.deps.Logger.Error("reset passkeys failed: transactional auditor unavailable")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "audit unavailable")
		return
	case err != nil:
		a.deps.Logger.Error("reset passkeys failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not reset passkeys")
		return
	}

	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.OkResponse{Code: gen.ErrorCodeOk, Message: "ok"})
}
