package api

import (
	"errors"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// Login validates credentials and issues an access/refresh pair.
func (a *AdminAPI) Login(c *gin.Context) {
	var req gen.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid login payload")
		return
	}
	email := string(req.Email)
	ip := c.ClientIP()

	// Track 1: per-IP token bucket.
	if !a.guard.AllowIP(ip) {
		abortError(c, http.StatusTooManyRequests, gen.ErrorCodeRateLimited, "too many login attempts")
		return
	}
	// Track 2: account+IP failure window.
	if a.guard.Locked(email, ip) {
		abortError(c, http.StatusTooManyRequests, gen.ErrorCodeRateLimited, "account temporarily locked")
		return
	}

	// Always run one Argon2id verification so the response time does not reveal
	// whether the email exists (CWE-208).
	dummyHash := dummyPasswordHash()

	var user model.User
	err := a.deps.DB.Where("email = ?", email).First(&user).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "login failed")
		return
	}
	hashToCheck := dummyHash
	if err == nil {
		hashToCheck = user.PasswordHash
	}
	valid := false
	if ok, verr := auth.VerifyPassword(hashToCheck, req.Password); verr == nil && err == nil {
		valid = ok
	}
	if !valid {
		a.guard.RecordFailure(email, ip)
		abortError(c, http.StatusUnauthorized, gen.ErrorCodeUnauthorized, "invalid credentials")
		return
	}

	a.guard.Reset(email, ip)

	// Issue #17: correct credentials are not enough — the mailbox must be
	// confirmed before any login path issues tokens.
	if err := auth.RequireVerifiedUser(user); err != nil {
		abortError(c, http.StatusForbidden, gen.ErrorCodeEmailNotVerified, "email is not verified")
		return
	}

	access, refresh, err := a.deps.Auth.IssueTokens(user.ID)
	if err != nil {
		a.deps.Logger.Error("issue tokens failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "login failed")
		return
	}

	c.JSON(http.StatusOK, gen.TokenResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data: gen.TokenPair{
			AccessToken:  access,
			RefreshToken: refresh,
			ExpiresIn:    int64(a.deps.AccessTTL.Seconds()),
		},
	})
}

// RefreshTokens rotates the refresh token and returns a new pair.
func (a *AdminAPI) RefreshTokens(c *gin.Context) {
	var req gen.RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid refresh payload")
		return
	}

	access, refresh, err := a.deps.Auth.RotateRefresh(req.RefreshToken)
	if err != nil {
		// Replay, expiry and unknown tokens are indistinguishable to the client:
		// it must log in again.
		abortError(c, http.StatusUnauthorized, gen.ErrorCodeUnauthorized, "refresh token rejected")
		return
	}

	c.JSON(http.StatusOK, gen.TokenResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data: gen.TokenPair{
			AccessToken:  access,
			RefreshToken: refresh,
			ExpiresIn:    int64(a.deps.AccessTTL.Seconds()),
		},
	})
}

// dummyPasswordHash is verified for unknown accounts to keep login timing flat.
var dummyPasswordHash = sync.OnceValue(func() string {
	hash, err := auth.HashPassword("dummy-password-for-timing")
	if err != nil {
		return ""
	}
	return hash
})
