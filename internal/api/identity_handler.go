package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/oidc"
)

// GetIdentities shows the caller's external bindings, including the conflict
// marker an operator needs to act on a poisoned binding.
func (a *AdminAPI) GetIdentities(c *gin.Context) {
	svc := a.oidc
	if svc == nil {
		abortError(c, http.StatusServiceUnavailable, gen.ErrorCodeInternal, "single sign-on is not enabled")
		return
	}
	uid, ok := requireUserID(c)
	if !ok {
		return
	}

	rows, err := svc.ListIdentities(c.Request.Context(), uid)
	if err != nil {
		a.deps.Logger.Error("list identities failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not list identities")
		return
	}

	items := make([]gen.Identity, 0, len(rows))
	for i := range rows {
		item := gen.Identity{
			Id:       int64(rows[i].ID),
			Provider: rows[i].Provider,
			Issuer:   rows[i].Issuer,
			Subject:  rows[i].Subject,
			Email:    rows[i].Email,
			LinkedAt: rows[i].LinkedAt,
		}
		if rows[i].LastLoginAt != nil {
			t := *rows[i].LastLoginAt
			item.LastLoginAt = &t
		}
		if rows[i].ConflictAt != nil {
			t := *rows[i].ConflictAt
			item.ConflictAt = &t
		}
		items = append(items, item)
	}

	c.JSON(http.StatusOK, gen.IdentityListResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data: gen.IdentityList{
			ActiveProvider: model.IdentityProviderOIDC,
			Identities:     items,
		},
	})
}

// UnlinkIdentity removes one binding after a second proof. Both the proof and
// the lockout predicate run before anything is deleted, so a failed request
// never leaves the account in a different state.
func (a *AdminAPI) UnlinkIdentity(c *gin.Context) {
	svc := a.oidc
	if svc == nil {
		abortError(c, http.StatusServiceUnavailable, gen.ErrorCodeInternal, "single sign-on is not enabled")
		return
	}
	uid, ok := requireUserID(c)
	if !ok {
		return
	}

	var req gen.IdentityUnlinkRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.IdentityId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "identity_id is required")
		return
	}

	stepup := req.StepupToken != nil && strings.TrimSpace(*req.StepupToken) != ""
	password := req.Password != nil && *req.Password != ""
	// Exactly one proof: two proofs means the client is confused about which
	// one is valid, and neither means nothing was proven.
	if stepup == password {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest,
			"provide exactly one of stepup_token or password")
		return
	}

	if stepup {
		if a.passkeys == nil {
			abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "passkey step-up is not available on this deployment")
			return
		}
		if err := a.passkeys.VerifyStepup(c.Request.Context(), uid, *req.StepupToken); err != nil {
			abortError(c, http.StatusUnauthorized, gen.ErrorCodeUnauthorized, "step-up rejected")
			return
		}
	} else {
		// The password is a credential oracle like /auth/password/remove, so it
		// reserves from the same authenticated management bucket (CWE-307).
		ip := c.ClientIP()
		account := fmt.Sprint(uid)
		if !a.totpManageGuard.AllowIP(ip) || !a.totpManageGuard.Reserve(account, ip) {
			abortError(c, http.StatusTooManyRequests, gen.ErrorCodeRateLimited, "too many attempts")
			return
		}
		user, err := a.loadUser(uid)
		if err != nil {
			a.deps.Logger.Error("load user failed")
			abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not verify password")
			return
		}
		if !auth.HasPassword(user) {
			// There is no password to check; pretending otherwise turns every
			// attempt into a 401 instead of telling the client which proof to use.
			abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest,
				"account has no password; use a passkey step-up")
			return
		}
		valid, err := auth.VerifyPassword(passwordHashForVerification(user.PasswordHash), *req.Password)
		if err != nil || !valid {
			abortError(c, http.StatusUnauthorized, gen.ErrorCodeUnauthorized, "invalid password")
			return
		}
		a.totpManageGuard.Reset(account, ip)
	}

	if err := svc.Unlink(c.Request.Context(), uid, uint(req.IdentityId)); err != nil {
		switch {
		case errors.Is(err, oidc.ErrIdentityNotFound):
			abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, "identity not found")
		case errors.Is(err, oidc.ErrLastCredential):
			abortError(c, http.StatusConflict, gen.ErrorCodeConflict,
				"unlinking this identity would leave the account with no credential")
		default:
			a.deps.Logger.Error("unlink identity failed")
			abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not unlink identity")
		}
		return
	}

	a.deps.Logger.Info("external identity unlinked", zap.Uint("user_id", uid), zap.Int64("identity_id", req.IdentityId))
	c.JSON(http.StatusOK, gen.OkResponse{Code: gen.ErrorCodeOk, Message: "ok"})
}
