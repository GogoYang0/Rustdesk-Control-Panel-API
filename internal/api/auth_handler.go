package api

import (
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
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

	// The captcha runs before any credential work: an automated caller without
	// a solution never reaches the password hash, and a captcha failure is not
	// a credential failure (it does not feed the lockout window).
	if !a.requireCaptcha(c, req.Captcha) {
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

	// Second factor: an enabled TOTP account receives a short challenge instead
	// of tokens. The password check above is not enough on its own.
	enabled, err := a.totp.Enabled(user.ID)
	if err != nil {
		a.deps.Logger.Error("load totp state failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "login failed")
		return
	}
	if enabled {
		challenge, err := a.deps.Issuer.IssueChallenge(user.ID, auth.ChallengeTTL)
		if err != nil {
			a.deps.Logger.Error("issue 2fa challenge failed")
			abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "login failed")
			return
		}
		data := map[string]any{"challenge_token": challenge}
		c.AbortWithStatusJSON(http.StatusUnauthorized, gen.ErrorResponse{
			Code:    gen.ErrorCodeTwoFactorRequired,
			Message: "two-factor authentication required",
			Data:    &data,
		})
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

	var plaintext string
	var row *model.APIToken
	ctx := c.Request.Context()
	err = a.deps.DB.Transaction(func(tx *gorm.DB) error {
		var cerr error
		plaintext, row, cerr = a.deps.Tokens.CreateTx(ctx, tx, uid, orgID, req.Name, normalized, ttl)
		if cerr != nil {
			return cerr
		}
		// The token and its audit entry commit together (issue #19): a token
		// that exists without a creation record must not be possible.
		tr, ok := a.deps.Auditor.(audit.TxRecorder)
		if !ok {
			return errAuditUnavailable
		}
		return tr.RecordTx(tx, audit.Entry{
			OrganizationID: orgID,
			ActorUserID:    uid,
			Action:         "token.create",
			TargetType:     "api_token",
			TargetID:       fmt.Sprint(row.ID),
			Detail: map[string]any{
				"name":        row.Name,
				"prefix":      row.TokenPrefix,
				"permissions": row.PermissionList(),
				"expires_at":  row.ExpiresAt,
			},
		})
	})
	switch {
	case errors.Is(err, auth.ErrTooManyTokens):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, err.Error())
		return
	case errors.Is(err, auth.ErrInvalidTokenInput):
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, err.Error())
		return
	case errors.Is(err, errAuditUnavailable):
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "audit unavailable")
		return
	case err != nil:
		a.deps.Logger.Error("create token failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not create token")
		return
	}

	// The domain audit record committed with the transaction; skip the
	// request-level fallback (the plaintext itself is never logged).
	c.Set(contextAuditRecorded, true)
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
	ctx := c.Request.Context()
	err := a.deps.DB.Transaction(func(tx *gorm.DB) error {
		row, rerr := a.deps.Tokens.RevokeTx(ctx, tx, uid, uint(tokenId))
		if rerr != nil {
			return rerr
		}
		tr, ok := a.deps.Auditor.(audit.TxRecorder)
		if !ok {
			return errAuditUnavailable
		}
		return tr.RecordTx(tx, audit.Entry{
			OrganizationID: row.OrganizationID,
			ActorUserID:    uid,
			Action:         "token.revoke",
			TargetType:     "api_token",
			TargetID:       fmt.Sprint(row.ID),
			Detail:         map[string]any{"name": row.Name, "prefix": row.TokenPrefix},
		})
	})
	switch {
	case errors.Is(err, auth.ErrTokenNotFound):
		abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, "token not found")
		return
	case errors.Is(err, errAuditUnavailable):
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "audit unavailable")
		return
	case err != nil:
		a.deps.Logger.Error("revoke token failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not revoke token")
		return
	}
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.OkResponse{Code: gen.ErrorCodeOk, Message: "ok"})
}

// SetupTOTP starts enrollment: it returns a pending secret and otpauth URI.
func (a *AdminAPI) SetupTOTP(c *gin.Context) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	secret, uri, err := a.totp.Setup(uid)
	switch {
	case errors.Is(err, auth.ErrTOTPAlreadyEnabled):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, err.Error())
		return
	case err != nil:
		a.deps.Logger.Error("totp setup failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not start two-factor setup")
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gen.TOTPSetupResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data:    gen.TOTPSetup{Secret: secret, OtpauthUri: uri},
	})
}

// EnableTOTP verifies the first code and activates two-factor.
func (a *AdminAPI) EnableTOTP(c *gin.Context) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	var req gen.TOTPCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.Code == "" {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "code is required")
		return
	}
	err := a.totp.Enable(uid, req.Code)
	switch {
	case errors.Is(err, auth.ErrTOTPAlreadyEnabled), errors.Is(err, auth.ErrTOTPNotSetup):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, err.Error())
		return
	case errors.Is(err, auth.ErrInvalidTOTP):
		abortError(c, http.StatusUnauthorized, gen.ErrorCodeUnauthorized, err.Error())
		return
	case err != nil:
		a.deps.Logger.Error("totp enable failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not enable two-factor")
		return
	}
	c.JSON(http.StatusOK, gen.OkResponse{Code: gen.ErrorCodeOk, Message: "ok"})
}

// DisableTOTP turns two-factor off after password and code verification.
func (a *AdminAPI) DisableTOTP(c *gin.Context) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	var req gen.TOTPDisableRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.Password == "" || req.Code == "" {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "password and code are required")
		return
	}
	// Disabling checks a password and a TOTP code, so it is a credential oracle
	// like the login second step (CWE-307). It has its own guard: the requests
	// are authenticated and legitimate management issues several in a row, so
	// they must not drain the unauthenticated login bucket — but a separate
	// per-IP bucket still bounds them once the failure table fills up. Reserve
	// spends the attempt up front, so concurrent requests cannot all pass a
	// separate lock check and overshoot the budget.
	ip := c.ClientIP()
	account := fmt.Sprint(uid)
	if !a.totpManageGuard.AllowIP(ip) || !a.totpManageGuard.Reserve(account, ip) {
		abortError(c, http.StatusTooManyRequests, gen.ErrorCodeRateLimited, "too many attempts")
		return
	}
	if err := a.totp.Disable(uid, req.Password, req.Code); err != nil {
		a.writeTOTPError(c, err, "disable two-factor failed")
		return
	}
	a.totpManageGuard.Reset(account, ip)
	c.JSON(http.StatusOK, gen.OkResponse{Code: gen.ErrorCodeOk, Message: "ok"})
}

// RegenerateRecoveryCodes replaces the one-time recovery codes.
func (a *AdminAPI) RegenerateRecoveryCodes(c *gin.Context) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	var req gen.TOTPDisableRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.Password == "" || req.Code == "" {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "password and code are required")
		return
	}
	// Same credential-oracle reasoning as DisableTOTP: the password and the
	// code are verified here, so attempts are reserved up front from the
	// dedicated management guard and reset after a success.
	ip := c.ClientIP()
	account := fmt.Sprint(uid)
	if !a.totpManageGuard.AllowIP(ip) || !a.totpManageGuard.Reserve(account, ip) {
		abortError(c, http.StatusTooManyRequests, gen.ErrorCodeRateLimited, "too many attempts")
		return
	}
	codes, err := a.totp.RegenerateRecovery(uid, req.Password, req.Code)
	if err != nil {
		a.writeTOTPError(c, err, "regenerate recovery codes failed")
		return
	}
	a.totpManageGuard.Reset(account, ip)
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gen.TOTPRecoveryCodesResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data:    gen.TOTPRecoveryCodes{Codes: codes},
	})
}

// VerifyTOTP completes a challenge login with a TOTP or recovery code.
func (a *AdminAPI) VerifyTOTP(c *gin.Context) {
	var req gen.TOTPVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.ChallengeToken == "" || req.Code == "" {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "challenge_token and code are required")
		return
	}
	// The challenge token carries the account but proves nothing about the
	// second factor, so this endpoint is a credential oracle like /auth/login
	// and shares the same two-track guard (CWE-307).
	ip := c.ClientIP()
	if !a.totpGuard.AllowIP(ip) {
		abortError(c, http.StatusTooManyRequests, gen.ErrorCodeRateLimited, "too many attempts")
		return
	}
	uid, err := a.deps.Issuer.ParseChallenge(req.ChallengeToken)
	if err != nil {
		abortError(c, http.StatusUnauthorized, gen.ErrorCodeUnauthorized, "invalid or expired challenge")
		return
	}
	account := fmt.Sprint(uid)
	if a.totpGuard.Locked(account, ip) {
		abortError(c, http.StatusTooManyRequests, gen.ErrorCodeRateLimited, "account temporarily locked")
		return
	}
	// Same ordering as the password step: the captcha runs before the factor
	// check, so a wrong proof never reaches the TOTP verification path.
	if !a.requireCaptcha(c, req.Captcha) {
		return
	}
	if err := a.totp.VerifyLogin(uid, req.Code); err != nil {
		if errors.Is(err, auth.ErrInvalidTOTP) || errors.Is(err, auth.ErrInvalidPassword) {
			a.totpGuard.RecordFailure(account, ip)
		}
		a.writeTOTPError(c, err, "2fa verify failed")
		return
	}
	a.totpGuard.Reset(account, ip)
	access, refresh, err := a.deps.Auth.IssueTokens(uid)
	if err != nil {
		a.deps.Logger.Error("issue tokens after 2fa failed")
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

// ResetMemberTOTP clears another member's two-factor configuration and records
// the administrator action in the same transaction.
func (a *AdminAPI) ResetMemberTOTP(c *gin.Context, orgId int64, userId int64) {
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
	// Resetting your own factor would turn the admin endpoint into a bypass of
	// the second factor itself (no password or TOTP proof is required here).
	// Self-service removal goes through /auth/2fa/disable, which verifies the
	// current code.
	if uint(userId) == uid {
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "cannot reset your own two-factor configuration")
		return
	}
	if _, err := a.loadMembership(uint(orgId), uint(userId)); err != nil {
		a.writeMemberError(c, err, "could not load membership")
		return
	}
	orgID, targetID := uint(orgId), uint(userId)
	err := a.deps.DB.Transaction(func(tx *gorm.DB) error {
		// Authorization is re-checked inside the transaction: 2FA state is
		// global per user, so org-local member.manage is not enough on its own.
		if err := a.assertResettableTOTP(tx, c, orgID, targetID); err != nil {
			return err
		}
		res := tx.Where("user_id = ?", userId).Delete(&model.UserTOTP{})
		if res.Error != nil {
			return res.Error
		}
		tr, ok := a.deps.Auditor.(audit.TxRecorder)
		if !ok {
			return errAuditUnavailable
		}
		return tr.RecordTx(tx, audit.Entry{
			OrganizationID: orgID,
			ActorUserID:    uid,
			Action:         "user.2fa.reset",
			TargetType:     "user",
			TargetID:       fmt.Sprint(userId),
			Detail:         map[string]any{"had_configuration": res.RowsAffected > 0},
		})
	})
	switch {
	case errors.Is(err, errTOTPOwnerReset):
		abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden, "only an owner can reset an owner's two-factor")
		return
	case errors.Is(err, errTOTPOtherOrgMembership):
		abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden, "target also belongs to another organization; account-wide two-factor recovery must be handled out of band")
		return
	case errors.Is(err, errAuditUnavailable):
		a.deps.Logger.Error("reset 2fa failed: transactional auditor unavailable")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "audit unavailable")
		return
	case err != nil:
		a.deps.Logger.Error("reset 2fa failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not reset two-factor")
		return
	}
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.OkResponse{Code: gen.ErrorCodeOk, Message: "ok"})
}

// assertResettableTOTP guards the global second factor of a user against
// tenant-local administrators: an owner inside the organization may only be
// reset by an owner (org.admin), and a user who belongs to any other
// organization must not be reset here at all — their factor also protects
// tenants this administrator does not control, and a non-owner there (say an
// administrator or a custom role) is just as exposed as an owner (CWE-269).
// Such multi-organization users recover their account out of band.
func (a *AdminAPI) assertResettableTOTP(tx *gorm.DB, c *gin.Context, orgID, targetID uint) error {
	var m model.Membership
	if err := store.ScopedByOrg(tx, orgID).Where("user_id = ?", targetID).First(&m).Error; err != nil {
		return err
	}
	var role model.Role
	if err := store.ScopedByOrg(tx, orgID).First(&role, m.RoleID).Error; err != nil {
		return err
	}
	if role.Kind == model.RoleKindOwner {
		perms, _ := authz.OrgPermissions(c)
		if !authz.Has(perms, authz.PermOrgAdmin) {
			return errTOTPOwnerReset
		}
	}
	var outside int64
	if err := store.WithoutTenantScope(tx).
		Model(&model.Membership{}).
		Where("user_id = ? AND organization_id <> ?", targetID, orgID).
		Count(&outside).Error; err != nil {
		return err
	}
	if outside > 0 {
		return errTOTPOtherOrgMembership
	}
	return nil
}

// errTOTPOwnerReset and errTOTPOtherOrgMembership refuse an administrator reset
// that would cross the authority boundary of the (global) second factor.
var (
	errTOTPOwnerReset         = errors.New("only an owner can reset an owner's two-factor")
	errTOTPOtherOrgMembership = errors.New("target belongs to another organization")
)

// writeTOTPError maps second-factor failures onto 401/409 responses.
func (a *AdminAPI) writeTOTPError(c *gin.Context, err error, logMsg string) {
	switch {
	case errors.Is(err, auth.ErrInvalidTOTP), errors.Is(err, auth.ErrInvalidPassword):
		// One message for both factors: saying which check failed would turn
		// every caller into a password/TOTP oracle.
		abortError(c, http.StatusUnauthorized, gen.ErrorCodeUnauthorized, "invalid password or code")
	case errors.Is(err, auth.ErrTOTPNotSetup), errors.Is(err, auth.ErrTOTPAlreadyEnabled):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, err.Error())
	default:
		a.deps.Logger.Error(logMsg)
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "two-factor operation failed")
	}
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
