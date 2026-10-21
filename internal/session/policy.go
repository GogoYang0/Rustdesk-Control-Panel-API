package session

import (
	"time"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// minutesPerDay is the modulo for minute-of-day arithmetic.
const minutesPerDay = 24 * 60

// Limits is the effective policy for one organization: every enabled policy
// applies at once and each dimension takes the strictest bound, so a caller does
// not choose a policy per request.
//
// The zero value is "no restriction" — which is why an empty policy list must
// produce exactly that, and why a policy set that intersects into nothing has to
// be represented separately (blocked) rather than as "no window".
type Limits struct {
	MaxConcurrent   *int64
	MaxMinutes      *int64
	RequireApproval bool

	// hasWindow reports whether any enabled policy constrained the window.
	// Without it, "no ranges" would be ambiguous between all day and blocked.
	hasWindow bool
	// blocked is set when the intersection is empty: the contract defines that
	// as fully blocked, and a policy set that silently allowed everything would
	// look configured while enforcing nothing.
	blocked bool
	window  []minuteRange
}

// minuteRange is a half-open interval [start, end) in UTC minutes-of-day, never
// wrapping: an overnight policy is split into two ranges.
type minuteRange struct {
	Start int64 `json:"start"`
	End   int64 `json:"end"`
}

// Effective folds the enabled policies into one limit.
func Effective(policies []model.Policy) Limits {
	var out Limits

	for _, p := range policies {
		if !p.Enabled {
			continue
		}
		out.MaxConcurrent = model.MinInt64(out.MaxConcurrent, p.MaxConcurrentSessions)
		out.MaxMinutes = model.MinInt64(out.MaxMinutes, p.MaxSessionMinutes)
		out.RequireApproval = out.RequireApproval || p.RequireApproval

		ranges, constrained := policyWindow(p)
		if !constrained {
			continue
		}
		if !out.hasWindow {
			out.hasWindow = true
			out.window = ranges
			continue
		}
		out.window = intersectRanges(out.window, ranges)
	}

	if out.hasWindow && len(out.window) == 0 {
		out.blocked = true
	}
	return out
}

// policyWindow returns the policy's window as non-wrapping ranges.
//
// constrained is false only when the policy allows all day, i.e. both bounds are
// unset. Everything else that is not a well-formed pair fails closed: a half
// window, an out-of-range value and start == end all yield an empty (blocked)
// window, because a policy that silently allowed everything would look
// configured while enforcing nothing. The write path rejects these with 400;
// this is the belt-and-braces reading for rows that were not written by it.
func policyWindow(p model.Policy) (ranges []minuteRange, constrained bool) {
	start, end := p.AllowedStartMinute, p.AllowedEndMinute
	if start == nil && end == nil {
		return nil, false
	}
	if start == nil || end == nil || !validMinute(*start) || !validMinute(*end) {
		return nil, true
	}
	s, e := *start, *end
	switch {
	case s == e:
		return nil, true // empty window
	case s < e:
		return []minuteRange{{Start: s, End: e}}, true
	default:
		// Overnight: [00:00, e) plus [s, 24:00). Emitted in ascending order
		// because intersectRanges walks both lists with a two-pointer merge.
		return []minuteRange{{Start: 0, End: e}, {Start: s, End: minutesPerDay}}, true
	}
}

// validMinute reports whether a stored minute-of-day is within the contract's
// 0–1439 range. Values outside it are a bad row, not a window.
func validMinute(m int64) bool {
	return m >= 0 && m < minutesPerDay
}

// intersectRanges returns the overlap of two sorted, disjoint range lists.
func intersectRanges(a, b []minuteRange) []minuteRange {
	out := make([]minuteRange, 0, len(a)+len(b))
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		start := max64(a[i].Start, b[j].Start)
		end := min64(a[i].End, b[j].End)
		if start < end {
			out = append(out, minuteRange{Start: start, End: end})
		}
		if a[i].End < b[j].End {
			i++
		} else {
			j++
		}
	}
	return out
}

// WithinWindow reports whether t is inside the allowed window. Times are
// compared as UTC minutes-of-day: the contract defines the window that way, so a
// local-zone host must not shift it.
func (l Limits) WithinWindow(t time.Time) bool {
	if l.blocked {
		return false
	}
	if !l.hasWindow {
		return true
	}
	utc := t.UTC()
	m := int64(utc.Hour()*60 + utc.Minute())
	for _, r := range l.window {
		if m >= r.Start && m < r.End {
			return true
		}
	}
	return false
}

// Snapshot is the JSON-friendly form of the limits, stored on a ticket at
// issuance time for audit and troubleshooting.
func (l Limits) Snapshot() map[string]any {
	snapshot := map[string]any{
		"max_concurrent_sessions": nil,
		"max_session_minutes":     nil,
		"require_approval":        l.RequireApproval,
	}
	if l.MaxConcurrent != nil {
		snapshot["max_concurrent_sessions"] = *l.MaxConcurrent
	}
	if l.MaxMinutes != nil {
		snapshot["max_session_minutes"] = *l.MaxMinutes
	}
	switch {
	case l.blocked:
		snapshot["window"] = []minuteRange{}
		snapshot["window_blocked"] = true
	case l.hasWindow:
		ranges := make([]minuteRange, len(l.window))
		copy(ranges, l.window)
		sortRanges(ranges)
		snapshot["window"] = ranges
	default:
		snapshot["window"] = nil // all day
	}
	return snapshot
}

func sortRanges(ranges []minuteRange) {
	for i := 1; i < len(ranges); i++ {
		for j := i; j > 0 && ranges[j].Start < ranges[j-1].Start; j-- {
			ranges[j], ranges[j-1] = ranges[j-1], ranges[j]
		}
	}
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
