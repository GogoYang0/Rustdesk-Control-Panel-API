package api

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/oidc"
)

// oidcFlowCookie binds one OIDC flow to the browser that started it.
const oidcFlowCookie = "oidc_flow"

// clearOIDCFlowCookie drops the binding once it is no longer needed.
func clearOIDCFlowCookie(c *gin.Context) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     oidcFlowCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// HandleOIDCCallback receives the IdP redirect. Every outcome is a 302 back to
// the SPA: a browser lands here, so an API-shaped error would strand the user on
// a blank page. The query carries either a one-shot ticket or a fixed code.
func (a *AdminAPI) HandleOIDCCallback(c *gin.Context, params gen.HandleOIDCCallbackParams) {
	svc := a.oidc
	if svc == nil {
		abortError(c, http.StatusServiceUnavailable, gen.ErrorCodeInternal, "single sign-on is not enabled")
		return
	}

	if !a.oidcGuard.AllowIP(c.ClientIP()) {
		abortError(c, http.StatusTooManyRequests, gen.ErrorCodeRateLimited, "too many sign-in attempts")
		return
	}

	state := ""
	if params.State != nil {
		state = *params.State
	}
	code := ""
	if params.Code != nil {
		code = *params.Code
	}
	// The IdP rejected the request, or omitted the code. The IdP's own error
	// text is deliberately dropped: it is untrusted input and can describe the
	// deployment.
	if params.Error != nil || code == "" {
		a.redirectOIDCError(c, svc, state, "oidc_failed")
		return
	}

	// The state must be the one this browser was handed at /start: without the
	// cookie check a forwarded callback URL would log the receiver in as the
	// original user (login CSRF).
	if cookie, err := c.Cookie(oidcFlowCookie); err != nil || cookie != state {
		a.redirectOIDCError(c, svc, state, "oidc_failed")
		return
	}

	res, err := svc.FinishCallback(c.Request.Context(), state, code)
	if err != nil {
		code := oidc.ErrorCode(err)
		a.deps.Logger.Warn("oidc callback rejected", zap.String("error_code", code))
		a.redirectOIDCError(c, svc, state, code)
		return
	}

	c.Redirect(http.StatusFound, oidcRedirectURL(a.deps.WebBaseURL, res.RedirectPath, "ticket", res.Ticket))
}

func (a *AdminAPI) redirectOIDCError(c *gin.Context, svc *oidc.Service, state, code string) {
	path := svc.RedirectPathFor(c.Request.Context(), state)
	c.Redirect(http.StatusFound, oidcRedirectURL(a.deps.WebBaseURL, path, "error", code))
}

// oidcRedirectURL joins the configured frontend origin with a path that was
// validated at /start time. Only the query parameter is added here, so a request
// can never steer the redirect off-site.
func oidcRedirectURL(base, path, key, value string) string {
	base = strings.TrimRight(base, "/")
	if path == "" {
		path = "/"
	}
	target, err := url.Parse(base + path)
	if err != nil {
		return base + "/"
	}
	q := target.Query()
	q.Set(key, value)
	target.RawQuery = q.Encode()
	return target.String()
}

// ExchangeOIDCLogin turns the ticket from the callback into a token pair.
func (a *AdminAPI) ExchangeOIDCLogin(c *gin.Context) {
	svc := a.oidc
	if svc == nil {
		abortError(c, http.StatusServiceUnavailable, gen.ErrorCodeInternal, "single sign-on is not enabled")
		return
	}

	var req gen.OIDCExchangeRequest
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Ticket) == "" {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "ticket is required")
		return
	}
	if !a.oidcGuard.AllowIP(c.ClientIP()) {
		abortError(c, http.StatusTooManyRequests, gen.ErrorCodeRateLimited, "too many sign-in attempts")
		return
	}

	// The ticket is bound to the browser that received the callback redirect:
	// a forwarded ticket must not be spendable by anyone else.
	flowState, err := svc.PeekStateForTicket(c.Request.Context(), req.Ticket)
	if err != nil {
		clearOIDCFlowCookie(c)
		abortError(c, http.StatusUnauthorized, gen.ErrorCodeUnauthorized, "ticket rejected")
		return
	}
	if cookie, cerr := c.Cookie(oidcFlowCookie); cerr != nil || cookie != flowState {
		clearOIDCFlowCookie(c)
		abortError(c, http.StatusUnauthorized, gen.ErrorCodeUnauthorized, "ticket rejected")
		return
	}

	user, err := svc.ExchangeTicket(c.Request.Context(), req.Ticket)
	if err != nil {
		// One message for expired, replayed and forged tickets: distinguishing
		// them tells an attacker whether a guess ever existed.
		abortError(c, http.StatusUnauthorized, gen.ErrorCodeUnauthorized, "ticket rejected")
		return
	}
	clearOIDCFlowCookie(c)
	a.finalizeExternalLogin(c, user, model.IdentityProviderOIDC)
}

// finalizeExternalLogin is the shared tail of every external login (OIDC now,
// LDAP later): mailbox gate, optional local second factor, then tokens.
func (a *AdminAPI) finalizeExternalLogin(c *gin.Context, user model.User, provider string) {
	if err := auth.RequireVerifiedUser(user); err != nil {
		abortError(c, http.StatusForbidden, gen.ErrorCodeEmailNotVerified, "email is not verified")
		return
	}

	if a.deps.RequireLocalSecondFactor {
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
			data := map[string]any{"challenge_token": challenge, "methods": []string{"totp"}}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gen.ErrorResponse{
				Code:    gen.ErrorCodeTwoFactorRequired,
				Message: "two-factor authentication required",
				Data:    &data,
			})
			return
		}
		// The switch means "do not skip an existing local factor", not "require
		// everyone to enrol"; accounts without TOTP would otherwise be locked
		// out with no way to set it up (design O12).
		a.deps.Logger.Warn("external login without local second factor",
			zap.Uint("user_id", user.ID), zap.String("provider", provider))
	}

	access, refresh, err := a.deps.Auth.IssueTokens(user.ID)
	if err != nil {
		a.deps.Logger.Error("issue tokens after external login failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "login failed")
		return
	}
	a.deps.Logger.Info("external login succeeded",
		zap.Uint("user_id", user.ID), zap.String("provider", provider))

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
