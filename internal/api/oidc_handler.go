package api

import (
	"errors"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/oidc"
)

// StartOIDCLogin hands the browser an authorization URL. It is unauthenticated
// by design: the whole point is to obtain credentials from the IdP.
func (a *AdminAPI) StartOIDCLogin(c *gin.Context) {
	svc := a.oidc
	if svc == nil {
		// 503 rather than 404: the endpoint exists, the deployment chose not to
		// configure it.
		abortError(c, http.StatusServiceUnavailable, gen.ErrorCodeInternal, "single sign-on is not enabled")
		return
	}
	var req gen.OIDCStartRequest
	if c.Request.Body != nil {
		if err := c.ShouldBindJSON(&req); err != nil && !errors.Is(err, io.EOF) {
			abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid payload")
			return
		}
	}
	redirectPath := ""
	if req.RedirectPath != nil {
		redirectPath = *req.RedirectPath
	}

	// Reject a malformed path before touching the guard: a client bug should
	// not burn the caller's sign-in budget.
	if _, err := oidc.SanitizeRedirectPath(redirectPath); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "redirect_path must be a site-internal path")
		return
	}
	if !a.oidcGuard.AllowIP(c.ClientIP()) {
		abortError(c, http.StatusTooManyRequests, gen.ErrorCodeRateLimited, "too many sign-in attempts")
		return
	}

	authURL, state, err := svc.Start(c.Request.Context(), redirectPath)
	switch {
	case errors.Is(err, oidc.ErrInvalidRedirect):
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "redirect_path must be a site-internal path")
		return
	case errors.Is(err, oidc.ErrProviderUnavailable):
		// Deliberately explicit: falling back to a password login would hide a
		// broken IdP integration from the operator.
		a.deps.Logger.Warn("oidc discovery unavailable")
		abortError(c, http.StatusServiceUnavailable, gen.ErrorCodeInternal, "identity provider is unavailable")
		return
	case err != nil:
		a.deps.Logger.Error("start oidc login failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not start sign-in")
		return
	}

	// Bind the flow to this browser: the callback and the exchange only accept
	// the request that carries this cookie, so a harvested callback or ticket
	// cannot log anyone else in (CWE-352).
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     oidcFlowCookie,
		Value:    state,
		Path:     "/",
		MaxAge:   int(svc.StateTTL().Seconds()) + 120,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gen.OIDCStartResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data:    gen.OIDCStart{AuthorizationUrl: authURL, State: state},
	})
}
