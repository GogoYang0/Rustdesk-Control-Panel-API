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
