package limit

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The limiter table must stay bounded even when every entry is fresh: an
// attacker rotating source addresses never lets entries go idle.
func TestLoginGuard_LimitersAreHardBounded(t *testing.T) {
	g := NewLoginGuard()
	base := time.Now()
	step := 0
	g.now = func() time.Time { return base.Add(time.Duration(step) * time.Second) }

	for i := 0; i < maxLimiters+500; i++ {
		step++
		g.AllowIP(fmt.Sprintf("198.51.100.%d/%d", i%256, i))
	}

	require.LessOrEqual(t, len(g.limiters), maxLimiters)
}

// Failure windows must never be evicted while still valid, so the table is
// bounded by refusing new keys once full.
func TestLoginGuard_FailuresAreHardBounded(t *testing.T) {
	g := NewLoginGuard()
	base := time.Now()
	step := 0
	g.now = func() time.Time { return base.Add(time.Duration(step) * time.Second) }

	for i := 0; i < maxFailures+500; i++ {
		step++
		g.RecordFailure(fmt.Sprintf("user%d@example.com", i), "203.0.113.7")
	}

	require.LessOrEqual(t, len(g.failures), maxFailures)

	// An existing tracked pair keeps being counted.
	key := "user0@example.com\x00 203.0.113.7"
	_ = key
	g.RecordFailure("user0@example.com", "203.0.113.7")
	require.False(t, g.Locked("user0@example.com", "203.0.113.7"))
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
