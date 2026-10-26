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
	require.True(t, reserve(u, "raw-token", time.Minute))
	require.NotContains(t, u.entries, "raw-token")
	require.Contains(t, u.entries, digestKey("raw-token"))
}

// reserve is the bool-shaped view used by the capacity tests.
func reserve(u *usedStore, key string, ttl time.Duration) bool {
	_, ok := u.Reserve(key, ttl)
	return ok
}

func TestUsedStore_ExpiredReservationIsReusable(t *testing.T) {
	now := time.Unix(1000, 0)
	u := newUsedStore(2, func() time.Time { return now })

	require.True(t, reserve(u, "a", time.Minute))
	now = now.Add(2 * time.Minute)
	require.True(t, reserve(u, "a", time.Minute))
}

// Capacity pressure must never re-open a proof that passed verification;
// pending reservations are the ones that give way.
func TestUsedStore_VerifiedEntrySurvivesCapacityPressure(t *testing.T) {
	now := time.Unix(1000, 0)
	u := newUsedStore(2, func() time.Time { return now })

	passed, ok := u.Reserve("passed", time.Minute)
	require.True(t, ok)
	u.MarkVerified(passed)
	require.True(t, reserve(u, "pending", time.Minute))

	require.True(t, reserve(u, "fresh", time.Minute))
	require.False(t, reserve(u, "passed", time.Minute), "a passed proof must not become replayable")
}

// A table made only of passed proofs refuses new reservations instead of
// dropping one of them.
func TestUsedStore_RefusesWhenEveryEntryPassed(t *testing.T) {
	now := time.Unix(1000, 0)
	u := newUsedStore(1, func() time.Time { return now })

	passed, ok := u.Reserve("passed", time.Minute)
	require.True(t, ok)
	u.MarkVerified(passed)
	require.False(t, reserve(u, "fresh", time.Minute))
	require.False(t, reserve(u, "passed", time.Minute))
}

// A reservation can be evicted while its provider call is still in flight; the
// verdict must then still be recorded, or the same proof could be submitted
// again.
func TestUsedStore_EvictedReservationIsRecordedWhenVerified(t *testing.T) {
	now := time.Unix(1000, 0)
	u := newUsedStore(1, func() time.Time { return now })

	inflight, ok := u.Reserve("passed", time.Minute)
	require.True(t, ok)
	require.True(t, reserve(u, "other", time.Minute), "the pending reservation is evicted to make room")

	u.MarkVerified(inflight)
	require.False(t, reserve(u, "passed", time.Minute), "a verified proof is recorded even when its reservation was evicted")
}

// A handle that lost its entry must not touch a newer reservation for the same
// key: neither promote it nor free it.
func TestUsedStore_StaleHandleLeavesANewerReservationAlone(t *testing.T) {
	now := time.Unix(1000, 0)
	u := newUsedStore(2, func() time.Time { return now })

	stale, ok := u.Reserve("token", time.Minute)
	require.True(t, ok)
	// The filler expires later, so eviction takes the token reservation first.
	require.True(t, reserve(u, "filler", 2*time.Minute))
	require.True(t, reserve(u, "fresh", time.Minute))

	current, ok := u.Reserve("token", time.Minute)
	require.True(t, ok, "the key is free again after its reservation was evicted")

	u.MarkVerified(stale)
	require.False(t, u.entries[digestKey("token")].verified, "a stale handle must not promote a newer reservation")
	u.Release(stale)
	require.Contains(t, u.entries, digestKey("token"), "a stale handle must not drop a newer reservation")

	u.Release(current)
	require.True(t, reserve(u, "token", time.Minute), "the current handle still releases the key")
}

func TestUsedStore_ReleaseFreesTheSlot(t *testing.T) {
	u := newUsedStore(1, nil)
	res, ok := u.Reserve("token", time.Minute)
	require.True(t, ok)
	u.Release(res)
	require.True(t, reserve(u, "token", time.Minute))
}
