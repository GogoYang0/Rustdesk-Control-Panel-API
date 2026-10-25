package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/captcha"
)

// GetCaptchaChallenge publishes the active captcha configuration and a fresh
// challenge. It is unauthenticated by design: the client needs it before it
// has any credential.
func (a *AdminAPI) GetCaptchaChallenge(c *gin.Context) {
	if !a.captcha.Enabled() {
		c.JSON(http.StatusOK, gen.CaptchaChallengeResponse{
			Code:    gen.ErrorCodeOk,
			Message: "ok",
			Data:    &gen.CaptchaChallenge{Enabled: false},
		})
		return
	}
	// A disabled captcha must not spend the bucket, so the limit only applies
	// to real challenge issuance. It stays separate from the login bucket: a
	// page refresh must not consume a login attempt.
	if !a.captchaGuard.AllowIP(c.ClientIP()) {
		abortError(c, http.StatusTooManyRequests, gen.ErrorCodeRateLimited, "too many captcha requests")
		return
	}

	challenge, err := a.captcha.Challenge(c.Request.Context())
	if err != nil {
		a.deps.Logger.Error("captcha challenge failed")
		abortError(c, http.StatusServiceUnavailable, gen.ErrorCodeCaptchaUnavailable, "captcha provider unavailable")
		return
	}
	provider := challenge.Provider
	c.JSON(http.StatusOK, gen.CaptchaChallengeResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data: &gen.CaptchaChallenge{
			Enabled:   true,
			Provider:  &provider,
			Challenge: &gen.CaptchaChallengePayload{Params: challenge.Params},
		},
	})
}

// requireCaptcha enforces the captcha on the public credential-checking
// endpoints. It returns false after writing the failure response. A captcha
// failure is deliberately not booked as a credential failure: the account lock
// belongs to password/TOTP attempts, and a provider outage must not lock users
// out of their own accounts.
func (a *AdminAPI) requireCaptcha(c *gin.Context, proof *gen.CaptchaProof) bool {
	if !a.captcha.Enabled() {
		return true
	}
	if proof == nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeCaptchaRequired, "captcha is required")
		return false
	}
	err := a.captcha.Verify(c.Request.Context(), captcha.Proof{Response: proof.Response})
	switch {
	case err == nil:
		return true
	case errors.Is(err, captcha.ErrRequired):
		abortError(c, http.StatusBadRequest, gen.ErrorCodeCaptchaRequired, "captcha is required")
		return false
	case errors.Is(err, captcha.ErrInvalid):
		// One opaque answer for expired, replayed and wrong proofs: the caller
		// must not learn anything about the account from this branch.
		abortError(c, http.StatusBadRequest, gen.ErrorCodeCaptchaInvalid, "captcha verification failed")
		return false
	default:
		a.deps.Logger.Error("captcha verification unavailable")
		abortError(c, http.StatusServiceUnavailable, gen.ErrorCodeCaptchaUnavailable, "captcha provider unavailable")
		return false
	}
}
