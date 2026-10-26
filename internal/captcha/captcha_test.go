package captcha

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestService_Disabled(t *testing.T) {
	s := Disabled()
	require.False(t, s.Enabled())

	// A disabled service must never reject: the callers short-circuit on
	// Enabled() and the service stays harmless if one forgets.
	require.NoError(t, s.Verify(context.Background(), Proof{}))
}
