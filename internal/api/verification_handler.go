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

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/mail"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// errEmailNotVerified is returned by requireVerifiedUser when a login is
// attempted with an account whose mailbox is not confirmed yet.
var errEmailNotVerified = errors.New("email not verified")

// errVerificationUsed aborts the redeem transaction when another request
// already consumed the token (single-use invariant).
var errVerificationUsed = errors.New("verification token already used")

// requireVerifiedUser gates every login path — the admin Login handler and,
// later, the compat layer (task 8) — on a confirmed mailbox (issue #17).
func requireVerifiedUser(u model.User) error {
	if !u.EmailVerified {
		return errEmailNotVerified
	}
	return nil
}

// VerifyEmail redeems a verification token: single-use and time-limited.
// Unknown, expired and already-used tokens all answer 409 so a leaked link
// reveals nothing about its state beyond "not redeemable".
func (a *AdminAPI) VerifyEmail(c *gin.Context) {
	var req gen.EmailVerificationRequest
	if err := c.ShouldBindJSON(&req); err != nil || len(req.Token) < 16 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid verification payload")
		return
	}

	var vt model.VerificationToken
	err := store.WithoutTenantScope(a.deps.DB).
		Where("token_hash = ? AND purpose = ?", hashToken(req.Token), model.VerificationPurposeEmail).
		First(&vt).Error
	if err != nil {
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "verification token is not valid")
		return
	}
	if a.deps.Now().After(vt.ExpiresAt) {
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "verification token has expired")
		return
	}

	// Marking the token used and flipping the user flag happen atomically:
	// a partial write would leave a verified user with a replayable token.
	err = a.deps.DB.Transaction(func(tx *gorm.DB) error {
		res := store.WithoutTenantScope(tx).
			Model(&model.VerificationToken{}).
			Where("id = ? AND used_at IS NULL", vt.ID).
			Update("used_at", a.deps.Now())
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return errVerificationUsed
		}
		return store.WithoutTenantScope(tx).
			Model(&model.User{}).
			Where("id = ?", vt.UserID).
			Update("email_verified", true).Error
	})
	switch {
	case errors.Is(err, errVerificationUsed):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "verification token was already used")
	case err != nil:
		a.deps.Logger.Error("verify email failed", zap.Error(err))
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not verify email")
	default:
		c.JSON(http.StatusOK, gen.OkResponse{Code: gen.ErrorCodeOk, Message: "ok"})
	}
}

// ResendVerification mails a fresh verification link. Whether or not the
// address exists the response is identical 200 (anti-enumeration); only a
// real unverified account actually triggers a mail.
func (a *AdminAPI) ResendVerification(c *gin.Context) {
	var req gen.ResendVerificationRequest
	if err := c.ShouldBindJSON(&req); err != nil || !strings.Contains(string(req.Email), "@") {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid email")
		return
	}

	// The endpoint triggers outbound email, so it shares the login-style
	// per-IP throttle: otherwise it becomes a mail-bombing relay (CWE-770).
	if !a.resend.allowIP(c.ClientIP()) {
		abortError(c, http.StatusTooManyRequests, gen.ErrorCodeRateLimited, "too many requests")
		return
	}

	var user model.User
	err := a.deps.DB.Where("email = ?", string(req.Email)).First(&user).Error
	if err == nil && !user.EmailVerified && !a.verificationCooldownActive(user.ID) {
		if serr := a.sendVerificationMail(c.Request.Context(), user); serr != nil {
			// A failed resend keeps the account state; the user can retry
			// after the cooldown, and the response must stay identical to
			// the unknown-address case anyway.
			a.deps.Logger.Warn("resend verification mail failed", zap.Uint("user_id", user.ID), zap.Error(serr))
		}
	}

	c.JSON(http.StatusOK, gen.OkResponse{Code: gen.ErrorCodeOk, Message: "ok"})
}

// verificationCooldownActive reports whether a token for this user was
// created too recently to justify another mail.
func (a *AdminAPI) verificationCooldownActive(userID uint) bool {
	var latest model.VerificationToken
	err := store.WithoutTenantScope(a.deps.DB).
		Where("user_id = ? AND purpose = ?", userID, model.VerificationPurposeEmail).
		Order("created_at DESC").
		First(&latest).Error
	if err != nil {
		return false
	}
	return a.deps.Now().Sub(latest.CreatedAt) < a.deps.ResendCooldown
}

// sendVerificationMail stores a fresh token and emails its redeem link.
// Unlike ResendVerification it is not throttled by the cooldown: callers
// use it for state transitions (account just created) where the mail must
// go out regardless of earlier tokens.
func (a *AdminAPI) sendVerificationMail(ctx context.Context, user model.User) error {
	token, err := newRandomToken()
	if err != nil {
		return err
	}
	vt := model.VerificationToken{
		UserID:    user.ID,
		TokenHash: hashToken(token),
		Purpose:   model.VerificationPurposeEmail,
		ExpiresAt: a.deps.Now().Add(a.deps.VerificationTTL),
	}
	if err := store.WithoutTenantScope(a.deps.DB).Create(&vt).Error; err != nil {
		return err
	}

	link := fmt.Sprintf("%s/verify-email?token=%s", strings.TrimRight(a.deps.WebBaseURL, "/"), token)
	hours := int(a.deps.VerificationTTL / time.Hour)
	if err := a.deps.Mailer.Send(ctx, mail.Message{
		To:      []string{user.Email},
		Subject: "请验证您的邮箱",
		TextBody: fmt.Sprintf("您好！\n\n请点击以下链接确认您的邮箱地址，验证后即可登录控制面板：\n\n%s\n\n"+
			"该链接 %d 小时内有效，且仅可使用一次。如果您没有注册过本服务，请忽略此邮件。\n", link, hours),
	}); err != nil {
		if errors.Is(err, mail.ErrDeliveryAccepted) {
			// The server may have accepted the message, so its link may be
			// sitting in the recipient's mailbox: the token stays valid and
			// the cooldown now legitimately protects it.
			return err
		}
		// Definite non-delivery: the link never went out, so drop only this
		// token — leaving it behind would make verificationCooldownActive
		// swallow the user's immediate retry through POST
		// /auth/resend-verification.
		if derr := store.WithoutTenantScope(a.deps.DB).Delete(&model.VerificationToken{}, vt.ID).Error; derr != nil {
			return fmt.Errorf("verification mail failed: %w; token cleanup failed: %v", err, derr)
		}
		return err
	}
	return nil
}
