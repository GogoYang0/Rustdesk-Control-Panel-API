package captcha

import (
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The stored key must not scale with the client-supplied string: an attacker
// controls the token length, so retention has to be bounded by the table size
// alone.
func TestDigestKey_IsFixedSizeAndStable(t *testing.T) {
	long := strings.Repeat("x", 4096)
	require.Len(t, digestKey(long), sha256.Size)
	require.Equal(t, digestKey(long), digestKey(long))
	require.NotEqual(t, digestKey("a"), digestKey("b"))
}

// Retention must not scale with the submitted string: the raw key never lands
// in the table.
func TestUsedStore_StoresDigestedKeys(t *testing.T) {
	u := newUsedStore(4, nil)
	require.True(t, u.Reserve("raw-token", time.Minute))
	require.NotContains(t, u.entries, "raw-token")
	require.Contains(t, u.entries, digestKey("raw-token"))
}

func TestUsedStore_ExpiredReservationIsReusable(t *testing.T) {
	now := time.Unix(1000, 0)
	u := newUsedStore(2, func() time.Time { return now })

	require.True(t, u.Reserve("a", time.Minute))
	now = now.Add(2 * time.Minute)
	require.True(t, u.Reserve("a", time.Minute))
}

// Capacity pressure must never re-open a proof that passed verification;
// pending reservations are the ones that give way.
func TestUsedStore_VerifiedEntrySurvivesCapacityPressure(t *testing.T) {
	now := time.Unix(1000, 0)
	u := newUsedStore(2, func() time.Time { return now })

	require.True(t, u.Reserve("passed", time.Minute))
	u.MarkVerified("passed")
	require.True(t, u.Reserve("pending", time.Minute))

	require.True(t, u.Reserve("fresh", time.Minute))
	require.False(t, u.Reserve("passed", time.Minute), "a passed proof must not become replayable")
}

// A table made only of passed proofs refuses new reservations instead of
// dropping one of them.
func TestUsedStore_RefusesWhenEveryEntryPassed(t *testing.T) {
	now := time.Unix(1000, 0)
	u := newUsedStore(1, func() time.Time { return now })

	require.True(t, u.Reserve("passed", time.Minute))
	u.MarkVerified("passed")
	require.False(t, u.Reserve("fresh", time.Minute))
	require.False(t, u.Reserve("passed", time.Minute))
}

func TestUsedStore_ReleaseFreesTheSlot(t *testing.T) {
	u := newUsedStore(1, nil)
	require.True(t, u.Reserve("token", time.Minute))
	u.Release("token")
	require.True(t, u.Reserve("token", time.Minute))
}
