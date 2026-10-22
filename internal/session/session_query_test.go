package session_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/session"
)

// seedSession writes one session for the harness organization.
func seedSession(t *testing.T, h *harness, startedAt time.Time, origin, status string) model.Session {
	t.Helper()
	actor := uint(1)
	row := model.Session{
		OrganizationID: h.org.ID,
		DeviceID:       h.device.ID,
		RustdeskID:     h.device.RustdeskID,
		ActorUserID:    &actor,
		Origin:         origin,
		Status:         status,
		StartedAt:      startedAt,
	}
	if status == model.SessionStatusOpen {
		row.LastActivityAt = &startedAt
	}
	require.NoError(t, h.db.Create(&row).Error)
	return row
}

func sessionEvent(t *testing.T, h *harness, sessionID uint, at time.Time, kind string) {
	t.Helper()
	require.NoError(t, h.db.Create(&model.SessionEvent{
		OrganizationID: h.org.ID,
		SessionID:      sessionID,
		Kind:           kind,
		At:             at,
		DetailJSON:     "{}",
	}).Error)
}

// The contract orders by started_at descending with id as the tiebreaker, so
// pagination is stable when several sessions share a second.
func TestListSessions_Ordering(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	base := time.Date(2026, 10, 22, 8, 0, 0, 0, time.UTC)
	older := seedSession(t, h, base.Add(-time.Hour), model.SessionOriginPanel, model.SessionStatusClosed)
	newer := seedSession(t, h, base, model.SessionOriginPanel, model.SessionStatusClosed)
	// Same second as `newer`: the id must break the tie.
	sameSecond := seedSession(t, h, base, model.SessionOriginNative, model.SessionStatusOpen)

	items, total, err := h.svc.ListSessions(ctx, h.org.ID, session.SessionFilter{})
	require.NoError(t, err)
	require.Equal(t, int64(3), total)
	require.Len(t, items, 3)
	require.Equal(t, sameSecond.ID, items[0].ID, "same second: newer id first")
	require.Equal(t, newer.ID, items[1].ID)
	require.Equal(t, older.ID, items[2].ID, "oldest last")
}

func TestListSessions_Filters(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	base := time.Date(2026, 10, 22, 8, 0, 0, 0, time.UTC)
	inWindow := seedSession(t, h, base, model.SessionOriginPanel, model.SessionStatusClosed)
	outside := seedSession(t, h, base.Add(3*time.Hour), model.SessionOriginNative, model.SessionStatusOpen)
	_ = outside

	panel := model.SessionOriginPanel
	items, _, err := h.svc.ListSessions(ctx, h.org.ID, session.SessionFilter{Origin: &panel})
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Equal(t, inWindow.ID, items[0].ID)

	closed := model.SessionStatusClosed
	items, _, err = h.svc.ListSessions(ctx, h.org.ID, session.SessionFilter{Status: &closed})
	require.NoError(t, err)
	require.Len(t, items, 1)

	device := h.device.ID
	items, _, err = h.svc.ListSessions(ctx, h.org.ID, session.SessionFilter{DeviceID: &device})
	require.NoError(t, err)
	require.Len(t, items, 2, "both sessions belong to the seeded device")

	since := base.Add(time.Hour)
	items, _, err = h.svc.ListSessions(ctx, h.org.ID, session.SessionFilter{Since: &since})
	require.NoError(t, err)
	require.Len(t, items, 1, "since is inclusive of its boundary")
	require.Equal(t, outside.ID, items[0].ID)

	until := base.Add(time.Hour)
	items, _, err = h.svc.ListSessions(ctx, h.org.ID, session.SessionFilter{Until: &until})
	require.NoError(t, err)
	require.Len(t, items, 1, "until is inclusive of its boundary")
	require.Equal(t, inWindow.ID, items[0].ID)
}

// Pagination: page defaults to 1, pageSize to 50 and is capped at 200; total is
// the unpaginated count so a client can drive its pager.
func TestListSessions_Pagination(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	base := time.Date(2026, 10, 22, 8, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		seedSession(t, h, base.Add(time.Duration(i)*time.Minute), model.SessionOriginPanel, model.SessionStatusClosed)
	}

	items, total, err := h.svc.ListSessions(ctx, h.org.ID, session.SessionFilter{})
	require.NoError(t, err)
	require.Equal(t, int64(5), total)
	require.Len(t, items, 5, "the default page size covers small sets")

	items, total, err = h.svc.ListSessions(ctx, h.org.ID, session.SessionFilter{Page: 2, PageSize: 2})
	require.NoError(t, err)
	require.Equal(t, int64(5), total, "total ignores pagination")
	require.Len(t, items, 2)
	require.Equal(t, base.Add(2*time.Minute), items[0].StartedAt.UTC(), "page 2 starts at the third newest")

	items, _, err = h.svc.ListSessions(ctx, h.org.ID, session.SessionFilter{Page: 99, PageSize: 2})
	require.NoError(t, err)
	require.Empty(t, items, "a page past the end is empty, not an error")

	// Out-of-range input is normalised rather than rejected: a pager that asks
	// for page 0 or a huge page must not 500.
	items, _, err = h.svc.ListSessions(ctx, h.org.ID, session.SessionFilter{Page: 0, PageSize: 0})
	require.NoError(t, err)
	require.Len(t, items, 5)

	items, _, err = h.svc.ListSessions(ctx, h.org.ID, session.SessionFilter{PageSize: 5000})
	require.NoError(t, err)
	require.Len(t, items, 5, "a page size above the cap is clamped, not fatal")
}

// Another organization's sessions are invisible, and a session id from another
// organization is simply not there.
func TestListSessions_TenantIsolation(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	mine := seedSession(t, h, time.Date(2026, 10, 22, 8, 0, 0, 0, time.UTC),
		model.SessionOriginPanel, model.SessionStatusClosed)

	other := modelOrganization(t, h)
	items, total, err := h.svc.ListSessions(ctx, other, session.SessionFilter{})
	require.NoError(t, err)
	require.Empty(t, items)
	require.Zero(t, total)

	_, _, _, err = h.svc.SessionDetail(ctx, other, mine.ID)
	require.ErrorIs(t, err, session.ErrSessionNotFound)
}

// The detail view carries the session and its timeline. Events are returned
// earliest-first and capped at 200, with a flag saying so — the oldest events
// are the audit-critical ones, so "latest 200" would drop exactly what an
// investigator needs first.
func TestSessionDetail_EventsAndTruncation(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	base := time.Date(2026, 10, 22, 8, 0, 0, 0, time.UTC)
	sess := seedSession(t, h, base, model.SessionOriginPanel, model.SessionStatusOpen)

	for i := 0; i < 205; i++ {
		sessionEvent(t, h, sess.ID, base.Add(time.Duration(i)*time.Second), "activity")
	}

	detail, events, truncated, err := h.svc.SessionDetail(ctx, h.org.ID, sess.ID)
	require.NoError(t, err)
	require.Equal(t, sess.ID, detail.ID)
	require.Len(t, events, 200)
	require.True(t, truncated, "more than 200 events must be reported")
	require.Equal(t, base, events[0].At.UTC(), "the earliest events are kept")
	require.Equal(t, base.Add(199*time.Second), events[199].At.UTC())

	// A short timeline is not truncated.
	short := seedSession(t, h, base.Add(time.Hour), model.SessionOriginPanel, model.SessionStatusClosed)
	sessionEvent(t, h, short.ID, base.Add(time.Hour), "started")
	_, events, truncated, err = h.svc.SessionDetail(ctx, h.org.ID, short.ID)
	require.NoError(t, err)
	require.Len(t, events, 1)
	require.False(t, truncated)
}

func TestSessionDetail_UnknownIsNotFound(t *testing.T) {
	h := newHarness(t)
	_, _, _, err := h.svc.SessionDetail(context.Background(), h.org.ID, 99999)
	require.ErrorIs(t, err, session.ErrSessionNotFound)
}
