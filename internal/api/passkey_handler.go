package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
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
