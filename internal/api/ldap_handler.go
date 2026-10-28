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
	// Track 2: account+IP failure window. The key is the lowercased username:
	// directory subjects are case-sensitive, but letting "Alice" and "alice"
	// hold separate windows would make the lockout trivially bypassable.
	guardKey := strings.ToLower(username)
	if a.guard.Locked(guardKey, ip) {
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
		a.guard.RecordFailure(guardKey, ip)
		// One message for both: which of the two failed would turn every caller
		// into a directory-enumeration oracle.
		a.deps.Logger.Warn("ldap login rejected",
			zap.String("username", username), zap.String("error_code", "invalid_credentials"))
		abortError(c, http.StatusUnauthorized, gen.ErrorCodeUnauthorized, "invalid credentials")
		return
	case errors.Is(err, ldapauth.ErrDirectoryUnavailable):
		// The stable code goes to dashboards, the wrapped cause (dial vs TLS vs
		// protocol) tells an outage from a misconfiguration; neither echoes
		// secrets — go-ldap errors carry result codes and messages, never the
		// bind password.
		a.deps.Logger.Warn("ldap directory unavailable",
			zap.String("username", username), zap.String("error_code", "directory_unavailable"), zap.Error(err))
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

	// A LDAP username is user-chosen and can be reassigned in the directory.
	// If the mailbox the directory now reports for a bound subject differs from
	// the bound one, freeze the binding: the old holder's account must not be
	// handed to the name's new holder. OIDC subjects are immutable `sub` values
	// and skip this check (O4 keeps the binding-wins rule there).
	if drift, err := a.identity.MarkSubjectEmailDrift(c.Request.Context(),
		model.IdentityProviderLDAP, a.ldapIssuer, guardKey, email); err != nil {
		a.deps.Logger.Error("check subject email drift failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "login failed")
		return
	} else if drift {
		a.deps.Logger.Warn("ldap binding frozen on directory mailbox change",
			zap.String("username", username), zap.String("error_code", "identity_conflict"))
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict,
			"directory mailbox changed; this binding needs an administrator reset")
		return
	}

	a.guard.Reset(guardKey, ip)

	// The subject is the lowercased username: uid/sAMAccountName match
	// case-insensitively in common directories, and binding the raw case would
	// turn a variant spelling into a bogus identity conflict on the next login.
	user, err := a.identity.Resolve(c.Request.Context(), identity.Claims{
		Provider:      model.IdentityProviderLDAP,
		Issuer:        a.ldapIssuer,
		Subject:       guardKey,
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
