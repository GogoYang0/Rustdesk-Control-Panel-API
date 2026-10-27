package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/passkey"
)

// RemovePassword turns the account into a passkey-only account. Every
// precondition is checked before the step-up token is burned, so a failed
// attempt does not cost the user a fresh assertion.
//
// Deviation from the design table: a wrong password answers 401, not 400 --
// it is a credential failure, and 401 is what every other credential check in
// this API returns.
func (a *AdminAPI) RemovePassword(c *gin.Context) {
	svc, ok := a.passkeysEnabled(c)
	if !ok {
		return
	}
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	var req gen.PasswordRemoveRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.Password == "" || req.StepupToken == "" {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "password and stepup_token are required")
		return
	}
	user, err := a.loadUser(uid)
	if err != nil {
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not remove password")
		return
	}
	if !auth.HasPassword(user) {
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "account has no password")
		return
	}

	count, err := svc.Count(c.Request.Context(), uid)
	if err != nil {
		a.deps.Logger.Error("count passkeys failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not remove password")
		return
	}
	if count < 2 {
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict,
			"at least two passkeys are required before the password can be removed")
		return
	}

	var totpCount int64
	if err := a.deps.DB.Model(&model.UserTOTP{}).Where("user_id = ?", uid).Count(&totpCount).Error; err != nil {
		a.deps.Logger.Error("load totp state failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not remove password")
		return
	}
	if totpCount > 0 {
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict,
			"disable two-factor authentication before removing the password")
		return
	}

	valid, err := auth.VerifyPassword(user.PasswordHash, req.Password)
	if err != nil || !valid {
		abortError(c, http.StatusUnauthorized, gen.ErrorCodeUnauthorized, "invalid credentials")
		return
	}
	if err := svc.VerifyStepup(c.Request.Context(), uid, req.StepupToken); err != nil {
		abortError(c, http.StatusUnauthorized, gen.ErrorCodeUnauthorized, "step-up token rejected")
		return
	}

	if err := a.deps.DB.Model(&model.User{}).Where("id = ?", uid).Update("password_hash", "").Error; err != nil {
		a.deps.Logger.Error("remove password failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not remove password")
		return
	}
	// Self-service security events have no tenant to file them under; they go
	// to the structured log only (design D15).
	a.deps.Logger.Info("local password removed",
		zap.Uint("user_id", uid), zap.Int64("passkey_count", count))

	c.JSON(http.StatusOK, gen.PasswordRemoveResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data: gen.PasswordRemoveResult{Warnings: []string{
			"compat_login_disabled",
			"keep_a_second_passkey",
		}},
	})
}

// SetPassword restores a local password on a passkey-only account.
func (a *AdminAPI) SetPassword(c *gin.Context) {
	svc, ok := a.passkeysEnabled(c)
	if !ok {
		return
	}
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	var req gen.PasswordSetRequest
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.NewPassword) == "" || req.StepupToken == "" {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "new_password and stepup_token are required")
		return
	}
	user, err := a.loadUser(uid)
	if err != nil {
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not set password")
		return
	}
	if auth.HasPassword(user) {
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "account already has a password")
		return
	}
	if err := svc.VerifyStepup(c.Request.Context(), uid, req.StepupToken); err != nil {
		if errors.Is(err, passkey.ErrStepupUsed) {
			abortError(c, http.StatusUnauthorized, gen.ErrorCodeUnauthorized, "step-up token already used")
			return
		}
		abortError(c, http.StatusUnauthorized, gen.ErrorCodeUnauthorized, "step-up token rejected")
		return
	}
	hash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "password must not be empty")
		return
	}
	if err := a.deps.DB.Model(&model.User{}).Where("id = ?", uid).Update("password_hash", hash).Error; err != nil {
		a.deps.Logger.Error("set password failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not set password")
		return
	}
	a.deps.Logger.Info("local password restored", zap.Uint("user_id", uid))
	c.JSON(http.StatusOK, gen.OkResponse{Code: gen.ErrorCodeOk, Message: "ok"})
}
