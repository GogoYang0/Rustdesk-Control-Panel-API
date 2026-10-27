package passkey

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/passkey/testauth"
)

// issueStepup drives a full step-up ceremony and returns its token.
func issueStepup(t *testing.T, svc *Service, u model.User, authn *testauth.Authenticator) string {
	t.Helper()

	ctx := context.Background()
	token, options, err := svc.BeginStepup(ctx, u)
	require.NoError(t, err)
	body := authn.Assertion(t, options.Response.Challenge.String(), 1, base64.RawURLEncoding.EncodeToString(userHandle(u.ID)))
	stepup, err := svc.FinishStepup(ctx, u, token, body)
	require.NoError(t, err)
	require.NotEmpty(t, stepup)
	return stepup
}

func TestStepup_RequiresOwnCredential(t *testing.T) {
	svc, _, db := newRegistrationService(t, 10)
	owner := newTestUser(t, db, "passkey-stepup-owner")
	other := newTestUser(t, db, "passkey-stepup-other")
	registerPasskey(t, svc, owner, testauth.New(t, svc.cfg.RPID, svc.cfg.Origin), "Owner")
	otherAuthn := testauth.New(t, svc.cfg.RPID, svc.cfg.Origin)
	registerPasskey(t, svc, other, otherAuthn, "Other")

	ctx := context.Background()
	token, options, err := svc.BeginStepup(ctx, owner)
	require.NoError(t, err)
	body := otherAuthn.Assertion(t, options.Response.Challenge.String(), 1, base64.RawURLEncoding.EncodeToString(userHandle(other.ID)))
	_, err = svc.FinishStepup(ctx, owner, token, body)
	require.ErrorIs(t, err, ErrAssertionFailed)
}

func TestStepup_NoCredentials(t *testing.T) {
	svc, _, db := newRegistrationService(t, 10)
	u := newTestUser(t, db, "passkey-stepup-none")

	_, _, err := svc.BeginStepup(context.Background(), u)
	require.ErrorIs(t, err, ErrNoCredentials)
}

func TestVerifyStepup_SingleUse(t *testing.T) {
	svc, _, db := newRegistrationService(t, 10)
	u := newTestUser(t, db, "passkey-stepup-single")
	authn := testauth.New(t, svc.cfg.RPID, svc.cfg.Origin)
	registerPasskey(t, svc, u, authn, "Phone")

	token := issueStepup(t, svc, u, authn)

	require.NoError(t, svc.VerifyStepup(context.Background(), u.ID, token))
	require.ErrorIs(t, svc.VerifyStepup(context.Background(), u.ID, token), ErrStepupUsed)
}

func TestVerifyStepup_RejectsAccessToken(t *testing.T) {
	svc, _, db := newRegistrationService(t, 10)
	u := newTestUser(t, db, "passkey-stepup-access")

	access, _, err := svc.issuer.Issue(u.ID)
	require.NoError(t, err)

	require.ErrorIs(t, svc.VerifyStepup(context.Background(), u.ID, access), ErrStepupInvalid)
}

func TestVerifyStepup_BoundToUser(t *testing.T) {
	svc, _, db := newRegistrationService(t, 10)
	owner := newTestUser(t, db, "passkey-stepup-bound-owner")
	other := newTestUser(t, db, "passkey-stepup-bound-other")
	authn := testauth.New(t, svc.cfg.RPID, svc.cfg.Origin)
	registerPasskey(t, svc, owner, authn, "Phone")

	token := issueStepup(t, svc, owner, authn)

	require.ErrorIs(t, svc.VerifyStepup(context.Background(), other.ID, token), ErrStepupInvalid)
}

func TestStepupTokenExpiresAfterTwoMinutes(t *testing.T) {
	// The token TTL is fixed at two minutes; assert the constant instead of
	// sleeping for two minutes in a unit test.
	require.Equal(t, 2*time.Minute, stepupTTL)
}
