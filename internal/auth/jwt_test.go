package auth_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
)

func TestParseAccess_Valid(t *testing.T) {
	iss := auth.NewIssuer("test-secret", time.Minute, time.Hour)

	access, _, err := iss.Issue(42)
	require.NoError(t, err)

	uid, err := iss.ParseAccess(access)
	require.NoError(t, err)
	require.EqualValues(t, 42, uid)
}

func TestParseAccess_Expired_Fails(t *testing.T) {
	// negative TTL means the token is already expired
	iss := auth.NewIssuer("test-secret", -time.Minute, time.Hour)

	access, _, err := iss.Issue(1)
	require.NoError(t, err)

	_, err = iss.ParseAccess(access)
	require.Error(t, err)
}

func TestParseAccess_WrongSecret_Fails(t *testing.T) {
	iss := auth.NewIssuer("secret-a", time.Minute, time.Hour)
	other := auth.NewIssuer("secret-b", time.Minute, time.Hour)

	access, _, err := iss.Issue(7)
	require.NoError(t, err)

	_, err = other.ParseAccess(access)
	require.Error(t, err)
}

func TestParseAccess_RefreshTokenRejected(t *testing.T) {
	iss := auth.NewIssuer("test-secret", time.Minute, time.Hour)

	_, refresh, err := iss.Issue(9)
	require.NoError(t, err)

	// refresh is an opaque token, not a JWT: it must not parse as an access token
	_, err = iss.ParseAccess(refresh)
	require.Error(t, err)
}
