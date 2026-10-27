package auth_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
)

func TestStepupToken_RoundTrip(t *testing.T) {
	issuer := auth.NewIssuer("test-secret-test-secret-test-secret", time.Minute, time.Hour)

	token, err := issuer.IssueStepup(42, "ceremony-handle", 2*time.Minute)
	require.NoError(t, err)

	uid, handle, err := issuer.ParseStepup(token)
	require.NoError(t, err)
	require.EqualValues(t, 42, uid)
	require.Equal(t, "ceremony-handle", handle)
}

func TestStepupToken_RejectsAccessToken(t *testing.T) {
	issuer := auth.NewIssuer("test-secret-test-secret-test-secret", time.Minute, time.Hour)

	access, _, err := issuer.Issue(7)
	require.NoError(t, err)

	_, _, err = issuer.ParseStepup(access)
	require.Error(t, err, "an access token must never authorize a step-up action")
}

func TestStepupToken_Expires(t *testing.T) {
	issuer := auth.NewIssuer("test-secret-test-secret-test-secret", time.Minute, time.Hour)

	token, err := issuer.IssueStepup(7, "handle", -time.Second)
	require.NoError(t, err)

	_, _, err = issuer.ParseStepup(token)
	require.Error(t, err)
}

func TestStepupToken_EmptyHandleRejected(t *testing.T) {
	issuer := auth.NewIssuer("test-secret-test-secret-test-secret", time.Minute, time.Hour)

	_, err := issuer.IssueStepup(7, "", time.Minute)
	require.Error(t, err)
}
