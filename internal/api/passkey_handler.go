package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/passkey"
)

// BeginPasskeyRegistration returns a creation challenge for the caller.
func (a *AdminAPI) BeginPasskeyRegistration(c *gin.Context) {
	svc, ok := a.passkeysEnabled(c)
	if !ok {
		return
	}
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	user, err := a.loadUser(uid)
	if err != nil {
		a.deps.Logger.Error("load user for passkey registration failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not start passkey registration")
		return
	}

	token, options, err := svc.BeginRegistration(c.Request.Context(), user)
	switch {
	case errors.Is(err, passkey.ErrTooManyPasskeys):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "too many passkeys for this account")
		return
	case err != nil:
		a.deps.Logger.Error("begin passkey registration failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not start passkey registration")
		return
	}

	payload, err := jsonObject(options)
	if err != nil {
		a.deps.Logger.Error("encode passkey registration options failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not start passkey registration")
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gen.PasskeyCeremonyResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data:    gen.PasskeyCeremony{CeremonyToken: token, Options: payload},
	})
}

// FinishPasskeyRegistration validates the browser's attestation and stores the
// credential.
func (a *AdminAPI) FinishPasskeyRegistration(c *gin.Context) {
	svc, ok := a.passkeysEnabled(c)
	if !ok {
		return
	}
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	var req gen.PasskeyRegistrationRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.CeremonyToken == "" || len(req.Credential) == 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "ceremony_token and credential are required")
		return
	}
	body, err := json.Marshal(req.Credential)
	if err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "credential is not valid JSON")
		return
	}
	user, err := a.loadUser(uid)
	if err != nil {
		a.deps.Logger.Error("load user for passkey registration failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not finish passkey registration")
		return
	}

	name := ""
	if req.Name != nil {
		name = *req.Name
	}
	created, err := svc.FinishRegistration(c.Request.Context(), user, req.CeremonyToken, body, name)
	switch {
	case errors.Is(err, passkey.ErrCeremonyNotFound),
		errors.Is(err, passkey.ErrCeremonyExpired),
		errors.Is(err, passkey.ErrCeremonyUsed),
		errors.Is(err, passkey.ErrAssertionFailed):
		abortError(c, http.StatusUnauthorized, gen.ErrorCodeUnauthorized, "passkey registration rejected")
		return
	case errors.Is(err, passkey.ErrCredentialExists), errors.Is(err, passkey.ErrTooManyPasskeys):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "credential already registered or limit reached")
		return
	case errors.Is(err, passkey.ErrInvalidName):
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "passkey name must be 1-64 characters")
		return
	case err != nil:
		a.deps.Logger.Error("finish passkey registration failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not finish passkey registration")
		return
	}

	a.deps.Logger.Info("passkey registered",
		zap.Uint("user_id", uid), zap.Uint("passkey_id", created.ID),
		zap.String("aaguid", created.AAGUID), zap.String("transports", created.Transports))

	c.JSON(http.StatusCreated, gen.PasskeyResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data:    passkeyToAPI(created),
	})
}

// passkeysEnabled answers 503 when the deployment did not enable WebAuthn:
// clients must be able to tell "switched off" from "wrong path".
func (a *AdminAPI) passkeysEnabled(c *gin.Context) (*passkey.Service, bool) {
	if a.passkeys == nil {
		abortError(c, http.StatusServiceUnavailable, gen.ErrorCodeInternal, "passkey login is not enabled")
		return nil, false
	}
	return a.passkeys, true
}

func (a *AdminAPI) loadUser(uid uint) (model.User, error) {
	var user model.User
	err := a.deps.DB.Where("id = ?", uid).First(&user).Error
	return user, err
}

// jsonObject converts a protocol struct into the free-form JSON object the
// contract exposes; the W3C shapes are consumed verbatim by the browser.
func jsonObject(v any) (map[string]any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func passkeyToAPI(row *model.UserPasskey) gen.Passkey {
	transports := []string{}
	if row.Transports != "" {
		_ = json.Unmarshal([]byte(row.Transports), &transports)
	}
	if transports == nil {
		transports = []string{}
	}
	return gen.Passkey{
		Id:             int64(row.ID),
		Name:           row.Name,
		CreatedAt:      row.CreatedAt,
		LastUsedAt:     row.LastUsedAt,
		Transports:     transports,
		BackupEligible: row.BackupEligible,
		BackupState:    row.BackupState,
		Aaguid:         row.AAGUID,
		CloneWarning:   row.CloneWarning,
	}
}

// BeginPasskeyLogin starts an assertion ceremony. The three entry modes are
// mutually exclusive: challenge_token (second factor after a password), email
// (a hint that only narrows allowCredentials) and neither (usernameless).
func (a *AdminAPI) BeginPasskeyLogin(c *gin.Context) {
	svc, ok := a.passkeysEnabled(c)
	if !ok {
		return
	}
	var req gen.PasskeyLoginBeginRequest
	if c.Request.Body != nil {
		if err := c.ShouldBindJSON(&req); err != nil && !errors.Is(err, io.EOF) {
			abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid passkey login payload")
			return
		}
	}
	if req.ChallengeToken != nil && req.Email != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "challenge_token and email are mutually exclusive")
		return
	}

	ip := c.ClientIP()
	if !a.passkeyGuard.AllowIP(ip) {
		abortError(c, http.StatusTooManyRequests, gen.ErrorCodeRateLimited, "too many passkey attempts")
		return
	}
	account := ""
	if req.Email != nil {
		account = strings.ToLower(strings.TrimSpace(*req.Email))
	}

	var user *model.User
	if req.ChallengeToken != nil {
		uid, err := a.deps.Issuer.ParseChallenge(*req.ChallengeToken)
		if err != nil {
			abortError(c, http.StatusUnauthorized, gen.ErrorCodeUnauthorized, "invalid or expired challenge")
			return
		}
		loaded, err := a.loadUser(uid)
		if err != nil {
			abortError(c, http.StatusUnauthorized, gen.ErrorCodeUnauthorized, "invalid or expired challenge")
			return
		}
		user = &loaded
	} else if account != "" {
		// A miss is not an error: the response shape must not reveal whether
		// the mailbox exists (design D16).
		var loaded model.User
		if err := a.deps.DB.Where("LOWER(email) = ?", account).First(&loaded).Error; err == nil {
			user = &loaded
		}
	}

	token, options, err := svc.BeginLogin(c.Request.Context(), user)
	if errors.Is(err, passkey.ErrNoCredentials) {
		if req.ChallengeToken != nil {
			abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "this account has no passkey")
			return
		}
		// A hint for an account without credentials degrades to the
		// usernameless ceremony instead of leaking the account state.
		token, options, err = svc.BeginLogin(c.Request.Context(), nil)
	}
	if err != nil {
		a.deps.Logger.Error("begin passkey login failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not start passkey login")
		return
	}

	payload, err := jsonObject(options)
	if err != nil {
		a.deps.Logger.Error("encode passkey login options failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not start passkey login")
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gen.PasskeyCeremonyResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data:    gen.PasskeyCeremony{CeremonyToken: token, Options: payload},
	})
}

// FinishPasskeyLogin validates the assertion and issues the same token pair as
// a password login. Passkey authentication is not stacked with a local TOTP
// step (design D1/D14).
func (a *AdminAPI) FinishPasskeyLogin(c *gin.Context) {
	svc, ok := a.passkeysEnabled(c)
	if !ok {
		return
	}
	var req gen.PasskeyLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.CeremonyToken == "" || len(req.Credential) == 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "ceremony_token and credential are required")
		return
	}
	body, err := json.Marshal(req.Credential)
	if err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "credential is not valid JSON")
		return
	}
	user, _, err := svc.FinishLogin(c.Request.Context(), req.CeremonyToken, body)
	switch {
	case errors.Is(err, passkey.ErrCloneWarning):
		a.deps.Logger.Warn("passkey signature counter regressed", zap.Uint("user_id", user.ID))
		abortError(c, http.StatusUnauthorized, gen.ErrorCodeUnauthorized, "passkey login rejected")
		return
	case errors.Is(err, passkey.ErrCeremonyNotFound),
		errors.Is(err, passkey.ErrCeremonyExpired),
		errors.Is(err, passkey.ErrCeremonyUsed),
		errors.Is(err, passkey.ErrAssertionFailed):
		abortError(c, http.StatusUnauthorized, gen.ErrorCodeUnauthorized, "passkey login rejected")
		return
	case err != nil:
		a.deps.Logger.Error("finish passkey login failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not finish passkey login")
		return
	}

	if err := auth.RequireVerifiedUser(user); err != nil {
		abortError(c, http.StatusForbidden, gen.ErrorCodeEmailNotVerified, "email is not verified")
		return
	}

	access, refresh, err := a.deps.Auth.IssueTokens(user.ID)
	if err != nil {
		a.deps.Logger.Error("issue tokens after passkey login failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "login failed")
		return
	}
	a.deps.Logger.Info("passkey login succeeded",
		zap.Uint("user_id", user.ID), zap.String("mode", "passkey"))
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

// ListPasskeys returns the caller's credentials plus the account state the UI
// needs to warn before deleting the last one.
func (a *AdminAPI) ListPasskeys(c *gin.Context) {
	svc, ok := a.passkeysEnabled(c)
	if !ok {
		return
	}
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	user, err := a.loadUser(uid)
	if err != nil {
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not list passkeys")
		return
	}
	rows, err := svc.List(c.Request.Context(), uid)
	if err != nil {
		a.deps.Logger.Error("list passkeys failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not list passkeys")
		return
	}
	totpEnabled, err := a.totp.Enabled(uid)
	if err != nil {
		a.deps.Logger.Error("load totp state failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not list passkeys")
		return
	}

	items := make([]gen.Passkey, 0, len(rows))
	for i := range rows {
		items = append(items, passkeyToAPI(&rows[i]))
	}
	c.JSON(http.StatusOK, gen.PasskeyListResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data: gen.PasskeyList{
			Items:       items,
			HasPassword: user.PasswordHash != "",
			TotpEnabled: totpEnabled,
		},
	})
}

// RenamePasskey changes one credential's display name.
func (a *AdminAPI) RenamePasskey(c *gin.Context, passkeyId int64) {
	svc, ok := a.passkeysEnabled(c)
	if !ok {
		return
	}
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if passkeyId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid passkey id")
		return
	}
	var req gen.PasskeyNameRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "name is required")
		return
	}
	updated, err := svc.Rename(c.Request.Context(), uid, uint(passkeyId), req.Name)
	switch {
	case errors.Is(err, passkey.ErrPasskeyNotFound):
		abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, "passkey not found")
		return
	case errors.Is(err, passkey.ErrInvalidName):
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "passkey name must be 1-64 characters")
		return
	case err != nil:
		a.deps.Logger.Error("rename passkey failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not rename passkey")
		return
	}
	a.deps.Logger.Info("passkey renamed",
		zap.Uint("user_id", uid), zap.Uint("passkey_id", updated.ID))
	c.JSON(http.StatusOK, gen.PasskeyResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data:    passkeyToAPI(updated),
	})
}

// DeletePasskey removes one credential unless that would lock the account out.
func (a *AdminAPI) DeletePasskey(c *gin.Context, passkeyId int64) {
	svc, ok := a.passkeysEnabled(c)
	if !ok {
		return
	}
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if passkeyId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid passkey id")
		return
	}
	err := svc.Delete(c.Request.Context(), uid, uint(passkeyId))
	switch {
	case errors.Is(err, passkey.ErrPasskeyNotFound):
		abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, "passkey not found")
		return
	case errors.Is(err, passkey.ErrLastCredential):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict,
			"cannot delete the last passkey of an account without a password")
		return
	case err != nil:
		a.deps.Logger.Error("delete passkey failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not delete passkey")
		return
	}
	a.deps.Logger.Info("passkey deleted", zap.Uint("user_id", uid), zap.Uint("passkey_id", uint(passkeyId)))
	c.JSON(http.StatusOK, gen.OkResponse{Code: gen.ErrorCodeOk, Message: "ok"})
}

// BeginPasskeyStepup starts a fresh assertion for a sensitive action.
func (a *AdminAPI) BeginPasskeyStepup(c *gin.Context) {
	svc, ok := a.passkeysEnabled(c)
	if !ok {
		return
	}
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	user, err := a.loadUser(uid)
	if err != nil {
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not start step-up")
		return
	}
	token, options, err := svc.BeginStepup(c.Request.Context(), user)
	switch {
	case errors.Is(err, passkey.ErrNoCredentials):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "this account has no passkey")
		return
	case err != nil:
		a.deps.Logger.Error("begin passkey stepup failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not start step-up")
		return
	}
	payload, err := jsonObject(options)
	if err != nil {
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not start step-up")
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gen.PasskeyCeremonyResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data:    gen.PasskeyCeremony{CeremonyToken: token, Options: payload},
	})
}

// FinishPasskeyStepup returns a single-use two-minute step-up token.
func (a *AdminAPI) FinishPasskeyStepup(c *gin.Context) {
	svc, ok := a.passkeysEnabled(c)
	if !ok {
		return
	}
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	var req gen.PasskeyLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.CeremonyToken == "" || len(req.Credential) == 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "ceremony_token and credential are required")
		return
	}
	body, err := json.Marshal(req.Credential)
	if err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "credential is not valid JSON")
		return
	}
	user, err := a.loadUser(uid)
	if err != nil {
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not finish step-up")
		return
	}

	stepup, err := svc.FinishStepup(c.Request.Context(), user, req.CeremonyToken, body)
	switch {
	case errors.Is(err, passkey.ErrCeremonyNotFound),
		errors.Is(err, passkey.ErrCeremonyExpired),
		errors.Is(err, passkey.ErrCeremonyUsed),
		errors.Is(err, passkey.ErrAssertionFailed),
		errors.Is(err, passkey.ErrCloneWarning):
		abortError(c, http.StatusUnauthorized, gen.ErrorCodeUnauthorized, "step-up rejected")
		return
	case err != nil:
		a.deps.Logger.Error("finish passkey stepup failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not finish step-up")
		return
	}
	a.deps.Logger.Info("passkey step-up succeeded", zap.Uint("user_id", uid))
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gen.StepupTokenResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data:    gen.StepupToken{StepupToken: stepup, ExpiresIn: 120},
	})
}
