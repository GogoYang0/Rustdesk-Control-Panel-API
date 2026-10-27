package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/identity"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/ldapauth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// LdapLogin authenticates against the directory and, on success, binds or
// reuses the external identity of the panel account with the same mailbox.
// The check order is the security argument: the empty-credential gate runs
// before the rate limiter and before anything can touch the directory (L1).
func (a *AdminAPI) LdapLogin(c *gin.Context) {
	dir := a.ldap
	if dir == nil {
		abortError(c, http.StatusServiceUnavailable, gen.ErrorCodeInternal, "directory login is not enabled")
		return
	}

	var req gen.LDAPLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid login payload")
		return
	}
	username := strings.TrimSpace(req.Username)
	password := req.Password
	// L1: an empty password plus a simple bind is an anonymous bind on many
	// directories, and the server answers success. Refuse before anything can
	// dial — the fake directory's dial counter is how the test proves it.
	if username == "" || password == "" {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "username and password are required")
		return
	}

	ip := c.ClientIP()
	// Track 1: per-IP token bucket, shared with /auth/login (design L9).
	if !a.guard.AllowIP(ip) {
		abortError(c, http.StatusTooManyRequests, gen.ErrorCodeRateLimited, "too many login attempts")
		return
	}
	// Track 2: account(username)+IP failure window.
	if a.guard.Locked(username, ip) {
		abortError(c, http.StatusTooManyRequests, gen.ErrorCodeRateLimited, "account temporarily locked")
		return
	}
	// The captcha runs before any credential work, exactly like /auth/login.
	if !a.requireCaptcha(c, req.Captcha) {
		return
	}

	email, err := dir.Authenticate(c.Request.Context(), username, password)
	switch {
	case errors.Is(err, ldapauth.ErrInvalidCredentials), errors.Is(err, ldapauth.ErrAmbiguousResult):
		a.guard.RecordFailure(username, ip)
		// One message for both: which of the two failed would turn every caller
		// into a directory-enumeration oracle.
		a.deps.Logger.Warn("ldap login rejected",
			zap.String("username", username), zap.String("error_code", "invalid_credentials"))
		abortError(c, http.StatusUnauthorized, gen.ErrorCodeUnauthorized, "invalid credentials")
		return
	case errors.Is(err, ldapauth.ErrDirectoryUnavailable):
		a.deps.Logger.Warn("ldap directory unavailable", zap.String("username", username))
		abortError(c, http.StatusServiceUnavailable, gen.ErrorCodeInternal, "directory service is unavailable")
		return
	case errors.Is(err, ldapauth.ErrMissingMail):
		a.deps.Logger.Warn("ldap entry has no mail attribute", zap.String("username", username))
		abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden, "directory account has no mail attribute")
		return
	case err != nil:
		a.deps.Logger.Error("ldap authentication failed unexpectedly")
		abortError(c, http.StatusServiceUnavailable, gen.ErrorCodeInternal, "directory service is unavailable")
		return
	}

	a.guard.Reset(username, ip)

	user, err := a.identity.Resolve(c.Request.Context(), identity.Claims{
		Provider:      model.IdentityProviderLDAP,
		Issuer:        a.ldapIssuer,
		Subject:       username,
		Email:         email,
		EmailVerified: true,
	})
	switch {
	case errors.Is(err, identity.ErrNoAccount):
		// No JIT (design §2): the mailbox must already belong to a panel account.
		a.deps.Logger.Warn("ldap login without a panel account", zap.String("username", username))
		abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden, "no panel account for this directory user")
		return
	case errors.Is(err, identity.ErrIdentityConflict):
		a.deps.Logger.Warn("ldap identity conflict", zap.String("username", username))
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "directory identity is bound to another account")
		return
	case errors.Is(err, identity.ErrEmailUnverified):
		abortError(c, http.StatusForbidden, gen.ErrorCodeEmailNotVerified, "email is not verified")
		return
	case err != nil:
		a.deps.Logger.Error("resolve ldap identity failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "login failed")
		return
	}

	if err := auth.RequireVerifiedUser(user); err != nil {
		abortError(c, http.StatusForbidden, gen.ErrorCodeEmailNotVerified, "email is not verified")
		return
	}

	a.finalizeExternalLogin(c, user, model.IdentityProviderLDAP)
}
