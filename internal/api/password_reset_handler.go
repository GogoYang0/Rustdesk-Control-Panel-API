package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/compatapi"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/mail"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

var (
	errPasswordResetUsed     = errors.New("password reset token already used")
	errPasswordResetNoPass   = errors.New("target has no local password")
	errPasswordResetDisabled = errors.New("target membership is disabled")
)

// RequestMemberPasswordReset mails a one-time reset link to a member. The
// link's plaintext token exists only in the message; the response and audit
// carry no credential material.
func (a *AdminAPI) RequestMemberPasswordReset(c *gin.Context, orgId int64, userId int64) {
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
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "cannot reset your own password")
		return
	}
	if _, err := a.loadMembership(uint(orgId), uint(userId)); err != nil {
		a.writeMemberError(c, err, "could not load membership")
		return
	}

	// This endpoint sends mail, so it shares the resend IP bucket. A per-target
	// cooldown additionally keeps one administrator from flooding a member.
	if !a.resend.AllowIP(c.ClientIP()) {
		abortError(c, http.StatusTooManyRequests, gen.ErrorCodeRateLimited, "too many requests")
		return
	}
	targetID := uint(userId)
	var latest model.VerificationToken
	if err := store.WithoutTenantScope(a.deps.DB).
		Where("user_id = ? AND purpose = ?", targetID, model.VerificationPurposePasswordReset).
		Order("created_at DESC").
		First(&latest).Error; err == nil && a.deps.Now().Sub(latest.CreatedAt) < a.deps.ResendCooldown {
		abortError(c, http.StatusTooManyRequests, gen.ErrorCodeRateLimited, "reset mail was sent recently")
		return
	}

	var token string
	var tokenID uint
	var target model.User
	err := a.deps.DB.Transaction(func(tx *gorm.DB) error {
		if _, err := lockActor(tx, uint(orgId), uid, false, authz.PermMemberManage); err != nil {
			return err
		}
		locked, err := lockUserForCredentialChange(tx, targetID)
		if err != nil {
			return err
		}
		target = locked
		if !auth.HasPassword(target) {
			return errPasswordResetNoPass
		}
		var membership model.Membership
		if err := store.ScopedByOrg(tx, uint(orgId)).
			Where("user_id = ?", targetID).
			First(&membership).Error; err != nil {
			return err
		}
		if membership.Disabled {
			return errPasswordResetDisabled
		}
		// Owner targets need org.admin, and account-wide resets are refused for
		// users who also belong elsewhere (same rule as factor resets).
		if err := a.assertResettableFactor(tx, c, uint(orgId), targetID); err != nil {
			return err
		}

		if err := store.WithoutTenantScope(tx).
			Where("user_id = ? AND purpose = ?", targetID, model.VerificationPurposePasswordReset).
			Delete(&model.VerificationToken{}).Error; err != nil {
			return err
		}
		fresh, err := newRandomToken()
		if err != nil {
			return err
		}
		vt := model.VerificationToken{
			UserID:    targetID,
			TokenHash: hashToken(fresh),
			Purpose:   model.VerificationPurposePasswordReset,
			ExpiresAt: a.deps.Now().Add(a.deps.PasswordResetTTL),
		}
		if err := store.WithoutTenantScope(tx).Create(&vt).Error; err != nil {
			return err
		}
		tr, ok := a.deps.Auditor.(audit.TxRecorder)
		if !ok {
			return errAuditUnavailable
		}
		if err := tr.RecordTx(tx, audit.Entry{
			OrganizationID: uint(orgId),
			ActorUserID:    uid,
			Action:         "user.password.reset_requested",
			TargetType:     "user",
			TargetID:       fmt.Sprint(targetID),
		}); err != nil {
			return err
		}
		token, tokenID = fresh, vt.ID
		return nil
	})
	switch {
	case errors.Is(err, errActorNoLongerAuthorized):
		abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden, "insufficient permissions")
		return
	case errors.Is(err, errFactorOwnerReset):
		abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden, "only an owner can reset an owner's password")
		return
	case errors.Is(err, errFactorOtherOrgMembership):
		abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden,
			"target also belongs to another organization; account-wide recovery must be handled out of band")
		return
	case errors.Is(err, gorm.ErrRecordNotFound):
		abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, "member not found")
		return
	case errors.Is(err, errPasswordResetNoPass):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "member has no local password")
		return
	case errors.Is(err, errPasswordResetDisabled):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "member is disabled")
		return
	case errors.Is(err, errAuditUnavailable):
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "audit unavailable")
		return
	case err != nil:
		a.deps.Logger.Error("request password reset failed", zap.Error(err))
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not reset password")
		return
	}
	c.Set(contextAuditRecorded, true)

	if err := a.sendPasswordResetMail(c.Request.Context(), target.Email, token); err != nil {
		if errors.Is(err, mail.ErrDeliveryAccepted) {
			// The server may have accepted the message; keep the token and tell
			// the administrator the request was accepted.
			a.deps.Logger.Warn("password reset mail accepted but delivery unconfirmed",
				zap.Uint("user_id", targetID))
		} else {
			if derr := store.WithoutTenantScope(a.deps.DB).
				Delete(&model.VerificationToken{}, tokenID).Error; derr != nil {
				a.deps.Logger.Error("password reset mail failed and token cleanup failed",
					zap.Uint("user_id", targetID), zap.Error(derr))
			}
			a.deps.Logger.Error("password reset mail failed", zap.Uint("user_id", targetID), zap.Error(err))
			abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not deliver reset email")
			return
		}
	}
	c.JSON(http.StatusOK, gen.OkResponse{Code: gen.ErrorCodeOk, Message: "ok"})
}

// ResetPassword redeems an admin-issued reset token. The token is checked
// before hashing so invalid attempts cannot burn CPU in the password hasher.
func (a *AdminAPI) ResetPassword(c *gin.Context) {
	var req gen.PasswordResetRequest
	if err := c.ShouldBindJSON(&req); err != nil || len(req.Token) < 16 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid reset payload")
		return
	}
	if len(req.NewPassword) < minPasswordLength || len(req.NewPassword) > 128 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest,
			"password must be between 8 and 128 characters")
		return
	}

	var vt model.VerificationToken
	err := store.WithoutTenantScope(a.deps.DB).
		Where("token_hash = ? AND purpose = ?", hashToken(req.Token), model.VerificationPurposePasswordReset).
		First(&vt).Error
	now := a.deps.Now()
	if err != nil || vt.UsedAt != nil || !now.Before(vt.ExpiresAt) {
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "reset link is not valid")
		return
	}
	hash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "password is not valid")
		return
	}

	err = a.deps.DB.Transaction(func(tx *gorm.DB) error {
		res := store.WithoutTenantScope(tx).
			Model(&model.VerificationToken{}).
			Where("id = ? AND used_at IS NULL AND expires_at > ?", vt.ID, now).
			Update("used_at", now)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected != 1 {
			return errPasswordResetUsed
		}
		target, err := lockUserForCredentialChange(tx, vt.UserID)
		if err != nil {
			return err
		}
		// The account may have become passkey-only since the mail was sent;
		// adding a password back requires the step-up flow, not this link.
		if !auth.HasPassword(target) {
			return errPasswordResetNoPass
		}
		if err := store.WithoutTenantScope(tx).
			Model(&model.User{}).
			Where("id = ?", vt.UserID).
			Update("password_hash", hash).Error; err != nil {
			return err
		}
		if err := auth.RevokeUserRefreshTokens(tx, vt.UserID, now); err != nil {
			return err
		}
		var memberships []model.Membership
		if err := store.WithoutTenantScope(tx).
			Where("user_id = ?", vt.UserID).
			Find(&memberships).Error; err != nil {
			return err
		}
		for _, membership := range memberships {
			if _, err := compatapi.RevokeOrgSessions(c.Request.Context(), tx,
				membership.OrganizationID, vt.UserID, now); err != nil {
				return err
			}
		}
		return nil
	})
	switch {
	case errors.Is(err, errPasswordResetUsed),
		errors.Is(err, errPasswordResetNoPass),
		errors.Is(err, gorm.ErrRecordNotFound):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "reset link is not valid")
		return
	case err != nil:
		a.deps.Logger.Error("reset password failed", zap.Error(err))
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not reset password")
		return
	}
	a.deps.Logger.Info("password reset completed", zap.Uint("user_id", vt.UserID))
	c.JSON(http.StatusOK, gen.OkResponse{Code: gen.ErrorCodeOk, Message: "ok"})
}

// lockUserForCredentialChange locks the account row across password/token
// mutations. SQLite has no SELECT ... FOR UPDATE and serialises writers.
func lockUserForCredentialChange(tx *gorm.DB, userID uint) (model.User, error) {
	query := store.WithoutTenantScope(tx)
	if tx.Name() != "sqlite" {
		query = query.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var user model.User
	err := query.First(&user, userID).Error
	return user, err
}

func (a *AdminAPI) sendPasswordResetMail(ctx context.Context, email, token string) error {
	link := fmt.Sprintf("%s/reset-password#token=%s", strings.TrimRight(a.deps.WebBaseURL, "/"), token)
	minutes := int(a.deps.PasswordResetTTL / time.Minute)
	return a.deps.Mailer.Send(ctx, mail.Message{
		To:      []string{email},
		Subject: "重置密码",
		TextBody: fmt.Sprintf("您好！\n\n管理员已为您发起密码重置。请点击以下链接设置新密码：\n\n%s\n\n"+
			"该链接 %d 分钟内有效，且仅可使用一次；重置后所有登录会话将被撤销。如果您不认识此操作，请联系组织管理员。\n",
			link, minutes),
	})
}
