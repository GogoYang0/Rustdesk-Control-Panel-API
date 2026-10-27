package passkey

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/passkey/testauth"
)

// loginAssertion builds the body a browser posts to the login finish endpoint.
func loginAssertion(t *testing.T, authn *testauth.Authenticator, challenge string, signCount uint32, userID uint) []byte {
	t.Helper()

	return authn.Assertion(t, challenge, signCount, base64.RawURLEncoding.EncodeToString(userHandle(userID)))
}

func TestLogin_WithUser(t *testing.T) {
	svc, _, db := newRegistrationService(t, 10)
	u := newTestUser(t, db, "passkey-login")
	authn := testauth.New(t, svc.cfg.RPID, svc.cfg.Origin)
	registerPasskey(t, svc, u, authn, "Phone")

	ctx := context.Background()
	token, options, err := svc.BeginLogin(ctx, &u)
	require.NoError(t, err)
	require.NotEmpty(t, options.Response.Challenge.String())

	got, row, err := svc.FinishLogin(ctx, token, loginAssertion(t, authn, options.Response.Challenge.String(), 1, u.ID))
	require.NoError(t, err)
	require.Equal(t, u.ID, got.ID)
	require.EqualValues(t, 1, row.SignCount)
	require.NotNil(t, row.LastUsedAt)
}

func TestLogin_Discoverable(t *testing.T) {
	svc, _, db := newRegistrationService(t, 10)
	u := newTestUser(t, db, "passkey-discoverable")
	authn := testauth.New(t, svc.cfg.RPID, svc.cfg.Origin)
	registerPasskey(t, svc, u, authn, "Phone")

	ctx := context.Background()
	token, options, err := svc.BeginLogin(ctx, nil)
	require.NoError(t, err)

	got, _, err := svc.FinishLogin(ctx, token, loginAssertion(t, authn, options.Response.Challenge.String(), 2, u.ID))
	require.NoError(t, err)
	require.Equal(t, u.ID, got.ID)
}

func TestLogin_ReplayFails(t *testing.T) {
	svc, _, db := newRegistrationService(t, 10)
	u := newTestUser(t, db, "passkey-replay-login")
	authn := testauth.New(t, svc.cfg.RPID, svc.cfg.Origin)
	registerPasskey(t, svc, u, authn, "Phone")

	ctx := context.Background()
	token, options, err := svc.BeginLogin(ctx, &u)
	require.NoError(t, err)
	body := loginAssertion(t, authn, options.Response.Challenge.String(), 1, u.ID)

	_, _, err = svc.FinishLogin(ctx, token, body)
	require.NoError(t, err)
	_, _, err = svc.FinishLogin(ctx, token, body)
	require.ErrorIs(t, err, ErrCeremonyUsed)
}

func TestLogin_RejectsCredentialOfAnotherUser(t *testing.T) {
	svc, _, db := newRegistrationService(t, 10)
	owner := newTestUser(t, db, "passkey-login-owner")
	other := newTestUser(t, db, "passkey-login-other")
	ownerAuthn := testauth.New(t, svc.cfg.RPID, svc.cfg.Origin)
	registerPasskey(t, svc, owner, ownerAuthn, "Phone")
	otherAuthn := testauth.New(t, svc.cfg.RPID, svc.cfg.Origin)
	registerPasskey(t, svc, other, otherAuthn, "Phone")

	ctx := context.Background()
	token, options, err := svc.BeginLogin(ctx, &owner)
	require.NoError(t, err)

	// A credential the allowed list does not contain must fail even though it
	// is a perfectly valid signature from another account.
	_, _, err = svc.FinishLogin(ctx, token, loginAssertion(t, otherAuthn, options.Response.Challenge.String(), 1, other.ID))
	require.ErrorIs(t, err, ErrAssertionFailed)
}

func TestLogin_SignCountZeroIsNotClone(t *testing.T) {
	svc, _, db := newRegistrationService(t, 10)
	u := newTestUser(t, db, "passkey-zerocount")
	authn := testauth.New(t, svc.cfg.RPID, svc.cfg.Origin)
	registerPasskey(t, svc, u, authn, "Phone")

	ctx := context.Background()
	for i := 0; i < 2; i++ {
		token, options, err := svc.BeginLogin(ctx, &u)
		require.NoError(t, err)
		_, row, err := svc.FinishLogin(ctx, token, loginAssertion(t, authn, options.Response.Challenge.String(), 0, u.ID))
		require.NoError(t, err)
		require.False(t, row.CloneWarning)
	}
}

func TestLogin_SignCountRegressionIsClone(t *testing.T) {
	svc, _, db := newRegistrationService(t, 10)
	u := newTestUser(t, db, "passkey-clone")
	authn := testauth.New(t, svc.cfg.RPID, svc.cfg.Origin)
	registerPasskey(t, svc, u, authn, "Phone")

	ctx := context.Background()
	token, options, err := svc.BeginLogin(ctx, &u)
	require.NoError(t, err)
	_, _, err = svc.FinishLogin(ctx, token, loginAssertion(t, authn, options.Response.Challenge.String(), 5, u.ID))
	require.NoError(t, err)

	token, options, err = svc.BeginLogin(ctx, &u)
	require.NoError(t, err)
	_, row, err := svc.FinishLogin(ctx, token, loginAssertion(t, authn, options.Response.Challenge.String(), 3, u.ID))
	require.ErrorIs(t, err, ErrCloneWarning)
	require.True(t, row.CloneWarning)

	var stored model.UserPasskey
	require.NoError(t, db.Where("user_id = ?", u.ID).First(&stored).Error)
	require.True(t, stored.CloneWarning)
	require.EqualValues(t, 5, stored.SignCount, "a regressed counter must not overwrite the stored high-water mark")
}

func TestLogin_NoCredentials(t *testing.T) {
	svc, _, db := newRegistrationService(t, 10)
	u := newTestUser(t, db, "passkey-none")

	_, _, err := svc.BeginLogin(context.Background(), &u)
	require.ErrorIs(t, err, ErrNoCredentials)
}
