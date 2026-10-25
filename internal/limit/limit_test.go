package limit

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The limiter table must stay bounded even when every entry is fresh: an
// attacker rotating source addresses never lets entries go idle. The clock
// is fixed so GC cannot remove anything and the cap is actually reached.
func TestLoginGuard_LimitersAreHardBounded(t *testing.T) {
	g := NewLoginGuard()
	g.now = func() time.Time { return time.Unix(1700000000, 0) }

	for i := 0; i < maxLimiters+500; i++ {
		g.AllowIP(fmt.Sprintf("198.51.100.%d/%d", i%256, i))
	}

	require.Equal(t, maxLimiters, len(g.limiters))
}

// Failure windows must never be evicted while still valid, so the table is
// bounded by refusing new keys once full. The clock is fixed so GC cannot
// remove anything and the cap is actually reached.
func TestLoginGuard_FailuresAreHardBounded(t *testing.T) {
	g := NewLoginGuard()
	g.now = func() time.Time { return time.Unix(1700000000, 0) }

	for i := 0; i < maxFailures+500; i++ {
		g.RecordFailure(fmt.Sprintf("user%d@example.com", i), "203.0.113.7")
	}

	require.Equal(t, maxFailures, len(g.failures))

	// A tracked, still-live pair keeps being counted while the table is
	// full: its lockout still triggers instead of silently resetting.
	for i := 1; i < failureLimit; i++ {
		g.RecordFailure("user0@example.com", "203.0.113.7")
	}
	require.True(t, g.Locked("user0@example.com", "203.0.113.7"))
}

func TestLoginGuard_LocksAfterFiveFailures(t *testing.T) {
	g := NewLoginGuard()
	for i := 0; i < failureLimit; i++ {
		require.False(t, g.Locked("a@example.com", "192.0.2.1"))
		g.RecordFailure("a@example.com", "192.0.2.1")
	}
	require.True(t, g.Locked("a@example.com", "192.0.2.1"))

	g.Reset("a@example.com", "192.0.2.1")
	require.False(t, g.Locked("a@example.com", "192.0.2.1"))
}

// Reserve spends one attempt up front so concurrent requests cannot all pass a
// separate check and then overshoot the budget: the fifth attempt is allowed,
// the sixth refused, and a successful credential check resets the window.
func TestLoginGuard_ReserveConsumesTheBudgetAtomically(t *testing.T) {
	g := NewLoginGuard()
	for i := 0; i < failureLimit; i++ {
		require.True(t, g.Reserve("a@example.com", "192.0.2.1"))
	}
	require.False(t, g.Reserve("a@example.com", "192.0.2.1"))

	g.Reset("a@example.com", "192.0.2.1")
	require.True(t, g.Reserve("a@example.com", "192.0.2.1"))
}

// A full failure table must refuse an untracked pair instead of letting it run
// unlimited attempts: the table cannot grow past its cap, and evicting a live
// window would silently reset somebody's lockout.
func TestLoginGuard_ReserveFailsClosedWhenFull(t *testing.T) {
	g := NewLoginGuard()
	g.now = func() time.Time { return time.Unix(1700000000, 0) }
	for i := 0; i < maxFailures; i++ {
		require.True(t, g.Reserve(fmt.Sprintf("user%d@example.com", i), "203.0.113.7"))
	}
	require.False(t, g.Reserve("new@example.com", "203.0.113.7"))
	// Already tracked pairs keep their remaining budget.
	require.True(t, g.Reserve("user0@example.com", "203.0.113.7"))
}
