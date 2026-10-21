package session_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/session"
)

func i64(v int64) *int64 { return &v }

// minute returns a UTC time at hh:mm.
func minute(hh, mm int) time.Time {
	return time.Date(2026, 10, 22, hh, mm, 0, 0, time.UTC)
}

func policy(name string, enabled bool) model.Policy {
	return model.Policy{Name: name, Enabled: enabled}
}

// No policy at all means no restriction: that is the documented default, and it
// must not accidentally mean "blocked".
func TestEffective_NoPoliciesMeansUnlimited(t *testing.T) {
	got := session.Effective(nil)

	require.Nil(t, got.MaxConcurrent)
	require.Nil(t, got.MaxMinutes)
	require.False(t, got.RequireApproval)
	require.True(t, got.WithinWindow(minute(3, 17)), "no window means all day")
	require.True(t, got.WithinWindow(minute(23, 59)))
}

// A disabled policy is inert: re-enabling must be an explicit act, not a side
// effect of another policy existing.
func TestEffective_DisabledPoliciesAreIgnored(t *testing.T) {
	disabled := policy("off", false)
	disabled.MaxConcurrentSessions = i64(1)
	disabled.RequireApproval = true
	disabled.AllowedStartMinute = i64(0)
	disabled.AllowedEndMinute = i64(1) // 00:00-00:01

	got := session.Effective([]model.Policy{disabled})

	require.Nil(t, got.MaxConcurrent)
	require.False(t, got.RequireApproval)
	require.True(t, got.WithinWindow(minute(12, 0)), "a disabled window must not apply")
}

// Per dimension the strictest bound wins; an unbounded policy never loosens a
// bounded one.
func TestEffective_TakesStrictestPerDimension(t *testing.T) {
	a := policy("a", true)
	a.MaxConcurrentSessions = i64(5)
	a.MaxSessionMinutes = i64(120)
	a.RequireApproval = false

	b := policy("b", true)
	b.MaxConcurrentSessions = i64(3)
	b.RequireApproval = true // one policy demanding approval is enough

	unbounded := policy("c", true) // nil everywhere

	got := session.Effective([]model.Policy{a, unbounded, b})

	require.Equal(t, int64(3), *got.MaxConcurrent, "3 is stricter than 5")
	require.Equal(t, int64(120), *got.MaxMinutes, "the only duration bound wins")
	require.True(t, got.RequireApproval, "any policy can demand approval")
}

// Windows intersect: a session must be allowed by every policy, not by any.
func TestEffective_WindowsIntersect(t *testing.T) {
	morning := policy("morning", true)
	morning.AllowedStartMinute = i64(540) // 09:00
	morning.AllowedEndMinute = i64(1020)  // 17:00

	afternoon := policy("afternoon", true)
	afternoon.AllowedStartMinute = i64(720) // 12:00
	afternoon.AllowedEndMinute = i64(1200)  // 20:00

	got := session.Effective([]model.Policy{morning, afternoon})

	require.False(t, got.WithinWindow(minute(11, 59)), "11:59 is outside the 12:00 start")
	require.True(t, got.WithinWindow(minute(12, 0)), "the interval is start-inclusive")
	require.True(t, got.WithinWindow(minute(16, 59)))
	require.False(t, got.WithinWindow(minute(17, 0)), "the interval is end-exclusive")
	require.False(t, got.WithinWindow(minute(19, 0)), "morning policy has closed by 19:00")
}

// start > end wraps over midnight, and the wrap must survive intersection.
func TestEffective_WindowsWrapOverMidnight(t *testing.T) {
	night := policy("night", true)
	night.AllowedStartMinute = i64(1320) // 22:00
	night.AllowedEndMinute = i64(360)    // 06:00

	lateNight := policy("late-night", true)
	lateNight.AllowedStartMinute = i64(1380) // 23:00
	lateNight.AllowedEndMinute = i64(420)    // 07:00

	got := session.Effective([]model.Policy{night, lateNight})

	require.False(t, got.WithinWindow(minute(22, 30)), "23:00 start excludes 22:30")
	require.True(t, got.WithinWindow(minute(23, 0)))
	require.True(t, got.WithinWindow(minute(3, 0)))
	require.True(t, got.WithinWindow(minute(5, 59)))
	require.False(t, got.WithinWindow(minute(6, 0)), "the stricter end is 06:00")
	require.False(t, got.WithinWindow(minute(12, 0)), "midday is outside both")
}

// Disjoint windows have an empty intersection, which the contract defines as
// fully blocked. Blocking is the safe reading: a policy that silently allowed
// everything would look configured while enforcing nothing.
func TestEffective_DisjointWindowsBlockEverything(t *testing.T) {
	morning := policy("morning", true)
	morning.AllowedStartMinute = i64(540) // 09:00
	morning.AllowedEndMinute = i64(600)   // 10:00

	evening := policy("evening", true)
	evening.AllowedStartMinute = i64(1200) // 20:00
	evening.AllowedEndMinute = i64(1260)   // 21:00

	got := session.Effective([]model.Policy{morning, evening})

	for _, hh := range []int{0, 9, 12, 20, 23} {
		require.False(t, got.WithinWindow(minute(hh, 0)), "%02d:00 must be blocked", hh)
	}
}

// One all-day policy plus one windowed policy: the window still applies.
func TestEffective_AllDayDoesNotWidenAWindow(t *testing.T) {
	allDay := policy("all-day", true)
	windowed := policy("office", true)
	windowed.AllowedStartMinute = i64(540)
	windowed.AllowedEndMinute = i64(1020)

	got := session.Effective([]model.Policy{allDay, windowed})

	require.False(t, got.WithinWindow(minute(8, 0)))
	require.True(t, got.WithinWindow(minute(9, 0)))
	require.False(t, got.WithinWindow(minute(17, 0)))
}
