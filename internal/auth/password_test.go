package auth_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
)

func TestHashVerify_RoundTrip(t *testing.T) {
	hash, err := auth.HashPassword("S3cret-Passw0rd!")
	require.NoError(t, err)
	require.NotEmpty(t, hash)

	ok, err := auth.VerifyPassword(hash, "S3cret-Passw0rd!")
	require.NoError(t, err)
	require.True(t, ok)
}

func TestVerify_WrongPassword_False(t *testing.T) {
	hash, err := auth.HashPassword("correct-password")
	require.NoError(t, err)

	ok, err := auth.VerifyPassword(hash, "wrong-password")
	require.NoError(t, err)
	require.False(t, ok)
}

func TestHash_UniqueSalts(t *testing.T) {
	h1, err := auth.HashPassword("same-plain-text")
	require.NoError(t, err)
	h2, err := auth.HashPassword("same-plain-text")
	require.NoError(t, err)
	require.NotEqual(t, h1, h2, "argon2id must use a random salt per hash")
}

func TestHash_FormatIsArgon2id(t *testing.T) {
	hash, err := auth.HashPassword("whatever")
	require.NoError(t, err)
	require.Regexp(t, `^\$argon2id\$`, hash)
}
