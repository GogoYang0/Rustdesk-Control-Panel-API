package api

import (
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
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

// ListTokens returns the caller's personal tokens of one organization. The
// endpoint is JWT-only: a personal token cannot manage tokens.
func (a *AdminAPI) ListTokens(c *gin.Context, params gen.ListTokensParams) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if params.OrganizationId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "organizationId is required")
		return
	}
	if _, ok := a.activeMembership(c, uid, uint(params.OrganizationId)); !ok {
		return
	}
	rows, err := a.deps.Tokens.List(c.Request.Context(), uid, uint(params.OrganizationId))
	if err != nil {
		a.deps.Logger.Error("list tokens failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not list tokens")
		return
	}
	c.Set(contextAuditRecorded, true)
	out := make([]gen.APIToken, 0, len(rows))
	for i := range rows {
		out = append(out, tokenToAPI(&rows[i]))
	}
	c.JSON(http.StatusOK, gen.APITokenListResponse{Code: gen.ErrorCodeOk, Message: "ok", Data: out})
}

// CreateToken mints a personal token bound to one organization. The requested
// permission set must be a subset of the caller's live role: a token must never
// be a way to exceed the human's own capabilities.
func (a *AdminAPI) CreateToken(c *gin.Context) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	var req gen.TokenCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid token payload")
		return
	}
	if req.OrganizationId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "organization_id is required")
		return
	}
	orgID := uint(req.OrganizationId)
	m, ok := a.activeMembership(c, uid, orgID)
	if !ok {
		return
	}
	role, err := a.deps.Roles.Resolve(orgID, *m)
	if err != nil {
		abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden, "membership role unavailable")
		return
	}
	allowed := role.PermissionList()
	requested := allowed
	if req.Permissions != nil {
		requested = *req.Permissions
	}
	normalized, err := authz.NormalizePermissions(requested)
	if err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, err.Error())
		return
	}
	for _, code := range normalized {
		if !authz.Has(allowed, code) {
			abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden, "token permissions must not exceed your current role")
			return
		}
	}

	ttl := auth.DefaultTokenTTL
	if req.ExpiresInDays != nil {
		if *req.ExpiresInDays < auth.MinTokenTTLDays || *req.ExpiresInDays > auth.MaxTokenTTLDays {
			abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "expires_in_days must be between 1 and 365")
			return
		}
		ttl = time.Duration(*req.ExpiresInDays) * 24 * time.Hour
	}

	plaintext, row, err := a.deps.Tokens.Create(c.Request.Context(), uid, orgID, req.Name, normalized, ttl)
	switch {
	case errors.Is(err, auth.ErrTooManyTokens):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, err.Error())
		return
	case errors.Is(err, auth.ErrInvalidTokenInput):
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, err.Error())
		return
	case err != nil:
		a.deps.Logger.Error("create token failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not create token")
		return
	}

	// The request-level audit fallback records token creation against the
	// token's organization (the plaintext itself is never logged).
	c.Set(contextOrgID, orgID)
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusCreated, gen.IssuedAPITokenResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data: gen.IssuedAPIToken{
			Token:     tokenToAPI(row),
			Plaintext: plaintext,
		},
	})
}

// RevokeToken revokes one of the caller's personal tokens.
func (a *AdminAPI) RevokeToken(c *gin.Context, tokenId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if tokenId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid token id")
		return
	}
	if err := a.deps.Tokens.Revoke(c.Request.Context(), uid, uint(tokenId)); err != nil {
		if errors.Is(err, auth.ErrTokenNotFound) {
			abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, "token not found")
			return
		}
		a.deps.Logger.Error("revoke token failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not revoke token")
		return
	}
	c.JSON(http.StatusOK, gen.OkResponse{Code: gen.ErrorCodeOk, Message: "ok"})
}

// activeMembership loads the caller's membership and fails closed when it is
// missing, disabled, or its role cannot be resolved.
func (a *AdminAPI) activeMembership(c *gin.Context, uid, orgID uint) (*model.Membership, bool) {
	m, err := a.loadMembership(orgID, uid)
	if err != nil {
		abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden, "not a member of this organization")
		return nil, false
	}
	if m.Disabled {
		abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden, "membership is disabled")
		return nil, false
	}
	return m, true
}

// tokenToAPI maps a stored token onto the wire shape (never the digest).
func tokenToAPI(t *model.APIToken) gen.APIToken {
	return gen.APIToken{
		Id:             int64(t.ID),
		OrganizationId: int64(t.OrganizationID),
		Name:           t.Name,
		TokenPrefix:    t.TokenPrefix,
		Permissions:    t.PermissionList(),
		ExpiresAt:      t.ExpiresAt,
		LastUsedAt:     t.LastUsedAt,
		RevokedAt:      t.RevokedAt,
		CreatedAt:      t.CreatedAt,
	}
}

// dummyPasswordHash is verified for unknown accounts to keep login timing flat.
var dummyPasswordHash = sync.OnceValue(func() string {
	hash, err := auth.HashPassword("dummy-password-for-timing")
	if err != nil {
		return ""
	}
	return hash
})
