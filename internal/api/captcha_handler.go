package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
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
