package api

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPasswordHashForVerification pins the constant-time branch: an account
// whose password was removed must still cost one Argon2id verification,
// otherwise the response time reveals which mailboxes are passwordless.
func TestPasswordHashForVerification(t *testing.T) {
	dummy := dummyPasswordHash()
	require.NotEmpty(t, dummy)

	require.Equal(t, dummy, passwordHashForVerification(""))
	require.Equal(t, "$argon2id$real", passwordHashForVerification("$argon2id$real"))
}

// TestPasswordLoginAccepted is the regression for the authentication bypass:
// a resolved account with no password must never authenticate, no matter what
// the hash comparison returned. The dummy hash is a real Argon2id hash of a
// known literal, so "the password matched" is true for it by construction.
func TestPasswordLoginAccepted(t *testing.T) {
	cases := []struct {
		name        string
		found       bool
		hasPassword bool
		matched     bool
		want        bool
	}{
		{"unknown account", false, false, false, false},
		{"unknown account with a matching dummy", false, false, true, false},
		{"passwordless account with a matching dummy", true, false, true, false},
		{"password account, wrong password", true, true, false, false},
		{"password account, correct password", true, true, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, passwordLoginAccepted(tc.found, tc.hasPassword, tc.matched))
		})
	}
}
