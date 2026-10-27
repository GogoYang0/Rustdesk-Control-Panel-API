package api_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/api"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/passkey"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/passkey/testauth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func adminPasskeyFixture(t *testing.T) (*harness, *passkey.Service, int64, model.User, string, string) {
	t.Helper()

	var svc *passkey.Service
	h, orgID, _, _, member, ownerToken, adminToken, _ := m4OrgWith(t, func(d *api.Deps) {
		built, err := passkey.NewService(d.DB, passkey.Config{
			RPID:               "panel.example.com",
			RPDisplayName:      "Panel",
			Origin:             "https://panel.example.com",
			CeremonyTTL:        300_000_000_000,
			CredentialsPerUser: 10,
		}, d.Issuer, nil)
		require.NoError(t, err)
		svc = built
		d.Passkeys = built
	})
	seedMemberPasskey(t, svc, member)
	return h, svc, orgID, member, ownerToken, adminToken
}

func seedMemberPasskey(t *testing.T, svc *passkey.Service, u model.User) {
	t.Helper()

	ctx := t.Context()
	authn := testauth.New(t, "panel.example.com", "https://panel.example.com")
	token, options, err := svc.BeginRegistration(ctx, u)
	require.NoError(t, err)
	body := authn.Attestation(t, options.Response.Challenge.String(), passkeyHandle(u.ID))
	_, err = svc.FinishRegistration(ctx, u, token, body, "Phone")
	require.NoError(t, err)
}

func TestResetMemberPasskeys_OwnerResetsMember(t *testing.T) {
	h, _, orgID, member, ownerToken, _ := adminPasskeyFixture(t)

	w := h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/members/"+itoa(int64(member.ID))+"/passkeys/reset", nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var count int64
	require.NoError(t, h.db.DB.Model(&model.UserPasskey{}).Where("user_id = ?", member.ID).Count(&count).Error)
	require.Zero(t, count)

	var audits int64
	// audit_logs is tenant-scoped: the raw handle needs an explicit bypass.
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.AuditLog{}).Where("action = ?", "user.passkey.reset").Count(&audits).Error)
	require.EqualValues(t, 1, audits)
}

func TestResetMemberPasskeys_Guards(t *testing.T) {
	h, _, orgID, member, ownerToken, adminToken := adminPasskeyFixture(t)

	// Admin cannot reset an owner (owner is the first seeded user).
	ownerID := int64(1)
	w := h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/members/"+itoa(ownerID)+"/passkeys/reset", nil, adminToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// A member without member.manage is refused before the self check.
	memberJWT := h.login(t, "m4-member@example.com", "password123")
	w = h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/members/"+itoa(int64(member.ID))+"/passkeys/reset", nil, memberJWT)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// Nobody resets their own credentials, including an owner.
	w = h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/members/1/passkeys/reset", nil, ownerToken)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
}

func TestResetMemberPasskeys_PasswordlessTargetConflicts(t *testing.T) {
	h, _, orgID, member, ownerToken, _ := adminPasskeyFixture(t)
	require.NoError(t, h.db.DB.Model(&model.User{}).Where("id = ?", member.ID).Update("password_hash", "").Error)

	w := h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/members/"+itoa(int64(member.ID))+"/passkeys/reset", nil, ownerToken)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())

	var count int64
	require.NoError(t, h.db.DB.Model(&model.UserPasskey{}).Where("user_id = ?", member.ID).Count(&count).Error)
	require.EqualValues(t, 1, count, "the refused reset must not delete credentials")
}
