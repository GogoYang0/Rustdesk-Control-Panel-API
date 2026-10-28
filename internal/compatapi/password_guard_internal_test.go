package compatapi

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPasswordLoginAccepted locks the compat credential decision: a resolved
// account without a password must never authenticate, even when the dummy hash
// matched the submitted password (it is a real hash of a known literal).
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
