package api_test

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/api"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/passkey"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/passkey/testauth"
)

const (
	passkeyRPID   = "panel.example.com"
	passkeyOrigin = "https://panel.example.com"
)

func passkeyHandle(userID uint) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(userID))
	return base64.RawURLEncoding.EncodeToString(buf)
}

type ceremonyView struct {
	CeremonyToken string `json:"ceremony_token"`
	Options       struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	} `json:"options"`
}

func passkeyHarness(t *testing.T, perUser int) (*harness, string, model.User) {
	t.Helper()

	h := newHarnessWith(t, func(d *api.Deps) {
		d.AuthSecret = "test-secret"
		svc, err := passkey.NewService(d.DB, passkey.Config{
			RPID:               passkeyRPID,
			RPDisplayName:      "Panel",
			Origin:             passkeyOrigin,
			CeremonyTTL:        5 * time.Minute,
			CredentialsPerUser: perUser,
		}, d.Issuer, nil)
		require.NoError(t, err)
		d.Passkeys = svc
	})
	u := h.seedUser(t, "passkey-http@example.com", "password123")
	return h, h.login(t, "passkey-http@example.com", "password123"), u
}

// beginRegistration drives the begin endpoint and returns the ceremony plus
// the challenge the authenticator must sign over.
func beginRegistration(t *testing.T, h *harness, jwt string) ceremonyView {
	t.Helper()

	w := h.do(t, http.MethodPost, "/api/v1/auth/passkey/register/begin", nil, jwt)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var view ceremonyView
	decodeData(t, w, &view)
	require.NotEmpty(t, view.CeremonyToken)
	require.NotEmpty(t, view.Options.PublicKey.Challenge)
	return view
}

func TestPasskeyRegister_HappyPath(t *testing.T) {
	h, jwt, u := passkeyHarness(t, 10)
	authn := testauth.New(t, passkeyRPID, passkeyOrigin)

	begin := beginRegistration(t, h, jwt)
	attestation := authn.Attestation(t, begin.Options.PublicKey.Challenge, passkeyHandle(u.ID))
	w := h.do(t, http.MethodPost, "/api/v1/auth/passkey/register/finish", map[string]any{
		"ceremony_token": begin.CeremonyToken,
		"credential":     mustDecode(t, attestation),
		"name":           "Laptop",
	}, jwt)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	var view struct {
		Id             int64    `json:"id"`
		Name           string   `json:"name"`
		Transports     []string `json:"transports"`
		BackupEligible bool     `json:"backup_eligible"`
		Aaguid         string   `json:"aaguid"`
	}
	decodeData(t, w, &view)
	require.NotZero(t, view.Id)
	require.Equal(t, "Laptop", view.Name)
	require.NotNil(t, view.Transports)
	require.Equal(t, "01020304-0506-0708-090a-0b0c0d0e0f10", view.Aaguid)

	var count int64
	require.NoError(t, h.db.DB.Model(&model.UserPasskey{}).Count(&count).Error)
	require.EqualValues(t, 1, count)
}

func TestPasskeyRegister_DisabledReturns503(t *testing.T) {
	h := newHarness(t)
	u := h.seedUser(t, "passkey-off@example.com", "password123")
	jwt := h.login(t, "passkey-off@example.com", "password123")
	_ = u

	w := h.do(t, http.MethodPost, "/api/v1/auth/passkey/register/begin", nil, jwt)
	require.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())
}

func TestPasskeyRegister_DuplicateCredentialConflicts(t *testing.T) {
	h, jwt, u := passkeyHarness(t, 10)
	authn := testauth.New(t, passkeyRPID, passkeyOrigin)

	begin := beginRegistration(t, h, jwt)
	w := h.do(t, http.MethodPost, "/api/v1/auth/passkey/register/finish", map[string]any{
		"ceremony_token": begin.CeremonyToken,
		"credential":     mustDecode(t, authn.Attestation(t, begin.Options.PublicKey.Challenge, passkeyHandle(u.ID))),
	}, jwt)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	// The same credential id cannot be bound twice, even for the same account.
	begin = beginRegistration(t, h, jwt)
	w = h.do(t, http.MethodPost, "/api/v1/auth/passkey/register/finish", map[string]any{
		"ceremony_token": begin.CeremonyToken,
		"credential":     mustDecode(t, authn.Attestation(t, begin.Options.PublicKey.Challenge, passkeyHandle(u.ID))),
	}, jwt)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
}

func TestPasskeyRegister_RejectedAssertionIs401(t *testing.T) {
	h, jwt, u := passkeyHarness(t, 10)
	evil := testauth.New(t, passkeyRPID, "https://evil.example.org")

	begin := beginRegistration(t, h, jwt)
	w := h.do(t, http.MethodPost, "/api/v1/auth/passkey/register/finish", map[string]any{
		"ceremony_token": begin.CeremonyToken,
		"credential":     mustDecode(t, evil.Attestation(t, begin.Options.PublicKey.Challenge, passkeyHandle(u.ID))),
	}, jwt)
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
}

func TestPasskeyRegister_RequiresJWT(t *testing.T) {
	h, _, _ := passkeyHarness(t, 10)

	w := h.do(t, http.MethodPost, "/api/v1/auth/passkey/register/begin", nil, "")
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
}

func mustDecode(t *testing.T, raw []byte) map[string]any {
	t.Helper()

	var out map[string]any
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}
