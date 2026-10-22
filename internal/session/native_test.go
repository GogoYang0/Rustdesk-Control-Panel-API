package session_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/session"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// A closed session is never reopened: a reconnect after a disconnect is a new
// session, which is what makes per-connection accounting meaningful.
func TestRecordLogEvent_ClosedSessionNotReused(t *testing.T) {
	h := newHarness(t)
	first, err := h.svc.RecordLogEvent(context.Background(), h.org.ID, h.device.ID, session.LogEventInput{
		Kind:       model.LogKindConn,
		OccurredAt: h.now.Add(-time.Minute),
	})
	require.NoError(t, err)
	_, err = h.svc.RecordLogEvent(context.Background(), h.org.ID, h.device.ID, session.LogEventInput{
		Kind:       "disconnected",
		OccurredAt: h.now.Add(-30 * time.Second),
	})
	require.NoError(t, err)
	closed := h.reloadSession(t, first.ID)
	require.Equal(t, model.SessionStatusClosed, closed.Status)

	second, err := h.svc.RecordLogEvent(context.Background(), h.org.ID, h.device.ID, session.LogEventInput{
		Kind:       model.LogKindConn,
		OccurredAt: h.now,
	})
	require.NoError(t, err)
	require.NotNil(t, second)
	require.NotEqual(t, first.ID, second.ID, "a reconnect is a new session")
}

// ── disconnected events ─────────────────────────────────────────────────────

// A disconnected event closes the device's open session with the disconnect
// reason, regardless of origin.
func TestRecordLogEvent_DisconnectedClosesSession(t *testing.T) {
	h := newHarness(t)
	native, err := h.svc.RecordLogEvent(context.Background(), h.org.ID, h.device.ID, session.LogEventInput{
		Kind:       model.LogKindConn,
		OccurredAt: h.now.Add(-5 * time.Minute),
	})
	require.NoError(t, err)

	sess, err := h.svc.RecordLogEvent(context.Background(), h.org.ID, h.device.ID, session.LogEventInput{
		Kind:       "disconnected",
		OccurredAt: h.now,
	})
	require.NoError(t, err)
	require.NotNil(t, sess)
	require.Equal(t, native.ID, sess.ID)

	reloaded := h.reloadSession(t, native.ID)
	require.Equal(t, model.SessionStatusClosed, reloaded.Status)
	require.NotNil(t, reloaded.EndedAt)
	require.Equal(t, h.now.UTC(), reloaded.EndedAt.UTC())
	require.NotNil(t, reloaded.EndReason)
	require.Equal(t, model.SessionEndDisconnected, *reloaded.EndReason)

	events := h.sessionEvents(t, native.ID)
	require.Len(t, events, 2)
	require.Equal(t, "disconnected", events[1].Kind)
}

// A disconnected event for a device without an open session is a no-op: the
// close half of a connection whose start was never seen.
func TestRecordLogEvent_DisconnectedWithoutOpenSession(t *testing.T) {
	h := newHarness(t)

	sess, err := h.svc.RecordLogEvent(context.Background(), h.org.ID, h.device.ID, session.LogEventInput{
		Kind:       "disconnected",
		OccurredAt: h.now,
	})
	require.NoError(t, err)
	require.Nil(t, sess, "nothing to close")
	require.Empty(t, h.alerts(t))
}

// A native connection outside the allowed window still gets its session (the
// panel cannot block it), but the violation is alerted.
func TestRecordLogEvent_NativeOutsideWindowAlerts(t *testing.T) {
	h := newHarness(t)
	h.addPolicy(t, func(p *model.Policy) {
		p.AllowedStartMinute = ptrInt64(9 * 60) // 09:00
		p.AllowedEndMinute = ptrInt64(17 * 60)  // 17:00
	})
	// 10:00 UTC is inside the window; move to 20:00.
	h.setClock(time.Date(2026, 10, 22, 20, 0, 0, 0, time.UTC))

	sess, err := h.svc.RecordLogEvent(context.Background(), h.org.ID, h.device.ID, session.LogEventInput{
		Kind:       model.LogKindConn,
		OccurredAt: h.now,
	})
	require.NoError(t, err)
	require.NotNil(t, sess, "native is record-only: the session is still created")

	alerts := h.alerts(t)
	require.Len(t, alerts, 1)
	require.Equal(t, model.AlertKindOutsideWindow, alerts[0].Kind)
	require.NotNil(t, alerts[0].SessionID)
	require.Equal(t, sess.ID, *alerts[0].SessionID)
	require.Equal(t, model.AlertSeverityWarning, alerts[0].Severity)
}

// Each connection is judged on its own: a session absorbs one conn event,
// and a second connection outside the window starts its own session with its
// own alert. What does not re-alert is activity *within* one session — the
// merged file/error lines never touch the window check.
func TestRecordLogEvent_EachConnectionAlertsOnce(t *testing.T) {
	h := newHarness(t)
	h.addPolicy(t, func(p *model.Policy) {
		p.AllowedStartMinute = ptrInt64(9 * 60)
		p.AllowedEndMinute = ptrInt64(17 * 60)
	})
	h.setClock(time.Date(2026, 10, 22, 20, 0, 0, 0, time.UTC))

	_, err := h.svc.RecordLogEvent(context.Background(), h.org.ID, h.device.ID, session.LogEventInput{
		Kind:       model.LogKindConn,
		OccurredAt: h.now,
	})
	require.NoError(t, err)
	_, err = h.svc.RecordLogEvent(context.Background(), h.org.ID, h.device.ID, session.LogEventInput{
		Kind:       model.LogKindConn,
		OccurredAt: h.now.Add(10 * time.Second),
	})
	require.NoError(t, err)

	require.Len(t, h.alerts(t), 2, "two connections, two violations, two alerts")
}

// A session started by an activity event (which does not judge the window —
// an activity line is not a connection) is judged when a conn event is
// absorbed into it, exactly once.
func TestRecordLogEvent_ConnAbsorbedIntoActivitySessionAlerts(t *testing.T) {
	h := newHarness(t)
	h.addPolicy(t, func(p *model.Policy) {
		p.AllowedStartMinute = ptrInt64(9 * 60)
		p.AllowedEndMinute = ptrInt64(17 * 60)
	})
	h.setClock(time.Date(2026, 10, 22, 20, 0, 0, 0, time.UTC))

	// The activity event starts the session without any window judgment.
	first, err := h.svc.RecordLogEvent(context.Background(), h.org.ID, h.device.ID, session.LogEventInput{
		Kind:       model.LogKindFile,
		OccurredAt: h.now,
	})
	require.NoError(t, err)
	require.Empty(t, h.alerts(t), "an activity line is not a connection")

	// The conn event is the connection: one judgment, one alert.
	sess, err := h.svc.RecordLogEvent(context.Background(), h.org.ID, h.device.ID, session.LogEventInput{
		Kind:       model.LogKindConn,
		OccurredAt: h.now.Add(10 * time.Second),
	})
	require.NoError(t, err)
	require.NotNil(t, sess)
	require.Equal(t, first.ID, sess.ID)

	alerts := h.alerts(t)
	require.Len(t, alerts, 1, "one connection, one window judgment")
}

// Events of another organization never merge into this organization's
// sessions, even for the same rustdesk id.
func TestRecordLogEvent_CrossTenantIsolation(t *testing.T) {
	h := newHarness(t)
	otherOrg := model.Organization{Name: "other"}
	require.NoError(t, h.db.Create(&otherOrg).Error)
	otherDev := model.Device{OrganizationID: otherOrg.ID, RustdeskID: h.device.RustdeskID, Name: "twin"}
	require.NoError(t, h.db.Create(&otherDev).Error)

	first, err := h.svc.RecordLogEvent(context.Background(), h.org.ID, h.device.ID, session.LogEventInput{
		Kind:       model.LogKindConn,
		OccurredAt: h.now,
	})
	require.NoError(t, err)

	second, err := h.svc.RecordLogEvent(context.Background(), otherOrg.ID, otherDev.ID, session.LogEventInput{
		Kind:       model.LogKindConn,
		OccurredAt: h.now.Add(5 * time.Second),
	})
	require.NoError(t, err)
	require.NotNil(t, second)
	require.NotEqual(t, first.ID, second.ID, "the other org gets its own session")
	require.Equal(t, otherOrg.ID, second.OrganizationID)

	// And the reverse: an event of this org's device does not touch the other
	// org's session either.
	otherSession := h.reloadSession(t, second.ID)
	require.NotNil(t, otherSession.LastActivityAt)
}

// ── idle sweep ──────────────────────────────────────────────────────────────

// The idle sweeper closes open sessions whose last activity (or start, when no
// activity was ever recorded) is older than the idle window.
func TestCloseIdleSessions(t *testing.T) {
	h := newHarness(t)

	idle, err := h.svc.RecordLogEvent(context.Background(), h.org.ID, h.device.ID, session.LogEventInput{
		Kind:       model.LogKindConn,
		OccurredAt: h.now.Add(-20 * time.Minute),
	})
	require.NoError(t, err)

	active, err := h.svc.RecordLogEvent(context.Background(), h.org.ID, h.device.ID, session.LogEventInput{
		Kind:       model.LogKindConn,
		OccurredAt: h.now.Add(-time.Minute),
	})
	require.NoError(t, err)
	require.NotEqual(t, idle.ID, active.ID, "the active session is separate (stale one left open)")

	// A session with no recorded activity falls back to started_at.
	noActivity := model.Session{
		OrganizationID: h.org.ID,
		DeviceID:       h.device.ID,
		RustdeskID:     h.device.RustdeskID,
		Origin:         model.SessionOriginNative,
		Status:         model.SessionStatusOpen,
		StartedAt:      h.now.Add(-20 * time.Minute),
	}
	require.NoError(t, h.db.Create(&noActivity).Error)

	changed, err := h.svc.CloseIdleSessions(context.Background(), h.now, 10*time.Minute)
	require.NoError(t, err)
	require.Equal(t, int64(2), changed, "the idle native and the no-activity session")

	idleRow := h.reloadSession(t, idle.ID)
	require.Equal(t, model.SessionStatusClosed, idleRow.Status)
	require.NotNil(t, idleRow.EndReason)
	require.Equal(t, model.SessionEndIdleTimeout, *idleRow.EndReason)

	noActivityRow := h.reloadSession(t, noActivity.ID)
	require.Equal(t, model.SessionStatusClosed, noActivityRow.Status)
	require.Equal(t, model.SessionEndIdleTimeout, *noActivityRow.EndReason)

	activeRow := h.reloadSession(t, active.ID)
	require.Equal(t, model.SessionStatusOpen, activeRow.Status, "the active session stays open")

	// The sweep is idempotent.
	changed, err = h.svc.CloseIdleSessions(context.Background(), h.now, 10*time.Minute)
	require.NoError(t, err)
	require.Equal(t, int64(0), changed)
}

// ── duration policy sweep ───────────────────────────────────────────────────

// Sessions running past max_session_minutes are closed by the background task
// and alerted — the real connection is not cut (the panel is not in the
// signalling path), so the alert is what the operator sees.
func TestClosePolicyExceededSessions(t *testing.T) {
	h := newHarness(t)
	h.addPolicy(t, func(p *model.Policy) { p.MaxSessionMinutes = ptrInt64(30) })

	long, err := h.svc.RecordLogEvent(context.Background(), h.org.ID, h.device.ID, session.LogEventInput{
		Kind:       model.LogKindConn,
		OccurredAt: h.now.Add(-45 * time.Minute),
	})
	require.NoError(t, err)
	fresh, err := h.svc.RecordLogEvent(context.Background(), h.org.ID, h.device.ID, session.LogEventInput{
		Kind:       model.LogKindConn,
		OccurredAt: h.now.Add(-5 * time.Minute),
	})
	require.NoError(t, err)

	changed, err := h.svc.ClosePolicyExceededSessions(context.Background(), h.now)
	require.NoError(t, err)
	require.Equal(t, int64(1), changed)

	longRow := h.reloadSession(t, long.ID)
	require.Equal(t, model.SessionStatusClosed, longRow.Status)
	require.Equal(t, model.SessionEndPolicyExceeded, *longRow.EndReason)

	freshRow := h.reloadSession(t, fresh.ID)
	require.Equal(t, model.SessionStatusOpen, freshRow.Status)

	alerts := h.alerts(t)
	require.Len(t, alerts, 1)
	require.Equal(t, model.AlertKindDurationExceeded, alerts[0].Kind)
	require.NotNil(t, alerts[0].SessionID)
	require.Equal(t, long.ID, *alerts[0].SessionID)

	// Idempotent: the closed session is not alerted twice.
	changed, err = h.svc.ClosePolicyExceededSessions(context.Background(), h.now)
	require.NoError(t, err)
	require.Equal(t, int64(0), changed)
	require.Len(t, h.alerts(t), 1)
}

// An organization without a duration policy never sweeps: null means
// unlimited.
func TestClosePolicyExceededSessions_NoPolicy(t *testing.T) {
	h := newHarness(t)
	_, err := h.svc.RecordLogEvent(context.Background(), h.org.ID, h.device.ID, session.LogEventInput{
		Kind:       model.LogKindConn,
		OccurredAt: h.now.Add(-10 * time.Hour),
	})
	require.NoError(t, err)

	changed, err := h.svc.ClosePolicyExceededSessions(context.Background(), h.now)
	require.NoError(t, err)
	require.Equal(t, int64(0), changed)
}

// ── T4-path alerts (the contract's alert sources) ───────────────────────────

// A redemption refused on the concurrency limit is alerted: the contract lists
// it as an alert source.
func TestRedeem_ConcurrencyExceededAlerts(t *testing.T) {
	h := newHarness(t)
	h.addPolicy(t, func(p *model.Policy) { p.MaxConcurrentSessions = ptrInt64(0) })

	ticket, token, err := h.svc.Issue(context.Background(), session.IssueInput{
		OrganizationID: h.org.ID, ActorUserID: 1, DeviceID: h.device.ID,
	})
	require.NoError(t, err)
	_, err = h.svc.Redeem(context.Background(), h.org.ID, 1, ticket.ID, token)
	require.ErrorIs(t, err, session.ErrConflict)

	alerts := h.alerts(t)
	require.Len(t, alerts, 1)
	require.Equal(t, model.AlertKindConcurrencyExceeded, alerts[0].Kind)
}

// An issuance refused outside the window is alerted (the denied session row
// already exists from T4; the alert is the inbox-facing record).
func TestIssue_OutsideWindowAlerts(t *testing.T) {
	h := newHarness(t)
	h.addPolicy(t, func(p *model.Policy) {
		p.AllowedStartMinute = ptrInt64(9 * 60)
		p.AllowedEndMinute = ptrInt64(17 * 60)
	})
	h.setClock(time.Date(2026, 10, 22, 20, 0, 0, 0, time.UTC))

	_, _, err := h.svc.Issue(context.Background(), session.IssueInput{
		OrganizationID: h.org.ID, ActorUserID: 1, DeviceID: h.device.ID,
	})
	require.ErrorIs(t, err, session.ErrOutsideWindow)

	alerts := h.alerts(t)
	require.Len(t, alerts, 1)
	require.Equal(t, model.AlertKindOutsideWindow, alerts[0].Kind)
}

// ── alerts listing ──────────────────────────────────────────────────────────

func TestListAlerts_OrdersAndFilters(t *testing.T) {
	h := newHarness(t)
	h.addPolicy(t, func(p *model.Policy) { p.MaxSessionMinutes = ptrInt64(8) })

	first, err := h.svc.RecordLogEvent(context.Background(), h.org.ID, h.device.ID, session.LogEventInput{
		Kind:       model.LogKindConn,
		OccurredAt: h.now.Add(-10 * time.Minute),
	})
	require.NoError(t, err)
	_, err = h.svc.RecordLogEvent(context.Background(), h.org.ID, h.device.ID, session.LogEventInput{
		Kind:       model.LogKindConn,
		OccurredAt: h.now.Add(-5 * time.Minute),
	})
	require.NoError(t, err)

	_, err = h.svc.ClosePolicyExceededSessions(context.Background(), h.now)
	require.NoError(t, err)

	items, total, err := h.svc.ListAlerts(context.Background(), h.org.ID, session.AlertFilter{})
	require.NoError(t, err)
	require.Equal(t, int64(1), total)
	require.Len(t, items, 1)
	require.Equal(t, model.AlertKindDurationExceeded, items[0].Kind)
	var detail map[string]any
	require.NoError(t, json.Unmarshal([]byte(items[0].DetailJSON), &detail))
	require.NotEmpty(t, detail, "the alert carries its violation context")
	_ = first

	// Newest first when several exist: seed one directly with a later clock.
	h.setClock(h.now.Add(time.Hour))
	_, err = h.svc.RecordLogEvent(context.Background(), h.org.ID, h.device.ID, session.LogEventInput{
		Kind:       model.LogKindConn,
		OccurredAt: h.now,
	})
	require.NoError(t, err)
	_, err = h.svc.ClosePolicyExceededSessions(context.Background(), h.now)
	require.NoError(t, err)

	items, total, err = h.svc.ListAlerts(context.Background(), h.org.ID, session.AlertFilter{
		Kind: ptrString(model.AlertKindDurationExceeded),
	})
	require.NoError(t, err)
	require.Equal(t, int64(2), total)
	require.Greater(t, items[0].CreatedAt, items[1].CreatedAt, "newest first")

	// Unknown kind filter matches nothing but is a valid filter (free string).
	items, total, err = h.svc.ListAlerts(context.Background(), h.org.ID, session.AlertFilter{
		Kind: ptrString("nope"),
	})
	require.NoError(t, err)
	require.Equal(t, int64(0), total)
	require.Empty(t, items)
}

func TestListAlerts_CrossTenantIsEmpty(t *testing.T) {
	h := newHarness(t)
	_, err := h.svc.RecordLogEvent(context.Background(), h.org.ID, h.device.ID, session.LogEventInput{
		Kind: model.LogKindConn, OccurredAt: h.now,
	})
	require.NoError(t, err)

	otherOrg := model.Organization{Name: "other"}
	require.NoError(t, h.db.Create(&otherOrg).Error)

	items, total, err := h.svc.ListAlerts(context.Background(), otherOrg.ID, session.AlertFilter{})
	require.NoError(t, err)
	require.Equal(t, int64(0), total)
	require.Empty(t, items)
}

// ── helpers ─────────────────────────────────────────────────────────────────

// seedPanelSession inserts an open panel session (as a redemption would).
func (h *harness) seedPanelSession(t *testing.T, deviceID uint, started time.Time) model.Session {
	t.Helper()
	sess := model.Session{
		OrganizationID: h.org.ID,
		DeviceID:       deviceID,
		RustdeskID:     h.device.RustdeskID,
		Origin:         model.SessionOriginPanel,
		Status:         model.SessionStatusOpen,
		TicketID:       nil,
		StartedAt:      started,
		LastActivityAt: &started,
	}
	require.NoError(t, store.WithoutTenantScope(h.db).Create(&sess).Error)
	return sess
}

func (h *harness) alerts(t *testing.T) []model.Alert {
	t.Helper()
	var alerts []model.Alert
	require.NoError(t, store.WithoutTenantScope(h.db).Order("id").Find(&alerts).Error)
	return alerts
}

func (h *harness) reloadSession(t *testing.T, id uint) model.Session {
	t.Helper()
	var sess model.Session
	require.NoError(t, store.WithoutTenantScope(h.db).First(&sess, id).Error)
	return sess
}

func ptrInt64(v int64) *int64 { return &v }

func (h *harness) sessionEvents(t *testing.T, sessionID uint) []model.SessionEvent {
	t.Helper()
	var events []model.SessionEvent
	require.NoError(t, store.WithoutTenantScope(h.db).
		Where("session_id = ?", sessionID).Order("at").Find(&events).Error)
	return events
}

// ── conn events ─────────────────────────────────────────────────────────────

// A conn event for a device without an open session starts a native session:
// native traffic is inferred from the log, the panel is not in the signalling
// path.
func TestRecordLogEvent_CreatesNativeSession(t *testing.T) {
	h := newHarness(t)

	sess, err := h.svc.RecordLogEvent(context.Background(), h.org.ID, h.device.ID, session.LogEventInput{
		Kind:       model.LogKindConn,
		OccurredAt: h.now,
	})
	require.NoError(t, err)
	require.NotNil(t, sess)
	require.Equal(t, model.SessionOriginNative, sess.Origin)
	require.Equal(t, model.SessionStatusOpen, sess.Status)
	require.Equal(t, h.device.ID, sess.DeviceID)
	require.Equal(t, h.device.RustdeskID, sess.RustdeskID)
	require.Equal(t, h.now.UTC(), sess.StartedAt.UTC())
	require.NotNil(t, sess.LastActivityAt)
	require.Nil(t, sess.TicketID, "native sessions never carry a ticket")

	events := h.sessionEvents(t, sess.ID)
	require.Len(t, events, 1)
	require.Equal(t, "connected", events[0].Kind, "the starting event is the session's connection")
}

// The contract caps absorption at one connection event per session: a second
// conn event means a second connection, and merging them would hide it (and
// with it its policy alerts).
func TestRecordLogEvent_SecondConnStartsNewNative(t *testing.T) {
	h := newHarness(t)
	first, err := h.svc.RecordLogEvent(context.Background(), h.org.ID, h.device.ID, session.LogEventInput{
		Kind:       model.LogKindConn,
		OccurredAt: h.now,
	})
	require.NoError(t, err)

	second, err := h.svc.RecordLogEvent(context.Background(), h.org.ID, h.device.ID, session.LogEventInput{
		Kind:       model.LogKindConn,
		OccurredAt: h.now.Add(10 * time.Second),
	})
	require.NoError(t, err)
	require.NotNil(t, second)
	require.NotEqual(t, first.ID, second.ID, "a session absorbs at most one conn event")

	reloaded := h.reloadSession(t, first.ID)
	require.NotNil(t, reloaded.LastActivityAt)
	require.Equal(t, h.now.UTC(), reloaded.LastActivityAt.UTC(), "the second event does not touch the first session")

	events := h.sessionEvents(t, first.ID)
	require.Len(t, events, 1, "connected only: the event that started this session")
}

// An activity event (file) merges into the single open native session and is
// recorded on its timeline.
func TestRecordLogEvent_ActivityMergesIntoNative(t *testing.T) {
	h := newHarness(t)
	first, err := h.svc.RecordLogEvent(context.Background(), h.org.ID, h.device.ID, session.LogEventInput{
		Kind:       model.LogKindConn,
		OccurredAt: h.now,
	})
	require.NoError(t, err)

	sess, err := h.svc.RecordLogEvent(context.Background(), h.org.ID, h.device.ID, session.LogEventInput{
		Kind:       model.LogKindFile,
		OccurredAt: h.now.Add(30 * time.Second),
	})
	require.NoError(t, err)
	require.NotNil(t, sess)
	require.Equal(t, first.ID, sess.ID, "a file event merges into the open session")

	events := h.sessionEvents(t, first.ID)
	require.Len(t, events, 2)
	require.Equal(t, model.LogKindFile, events[1].Kind, "the event itself is recorded")
}

// With panel and native candidates open at once, an activity event refreshes
// all of them and is recorded only on the native session(s): "panel first"
// would let the native session idle out and its duration alerts vanish.
func TestRecordLogEvent_ActivityRefreshesAllCandidates(t *testing.T) {
	h := newHarness(t)
	panel := h.seedPanelSession(t, h.device.ID, h.now.Add(-time.Minute))
	// The panel absorbs its one connection...
	_, err := h.svc.RecordLogEvent(context.Background(), h.org.ID, h.device.ID, session.LogEventInput{
		Kind:       model.LogKindConn,
		OccurredAt: h.now.Add(-45 * time.Second),
	})
	require.NoError(t, err)
	// ...so this second connection starts its own native session.
	native, err := h.svc.RecordLogEvent(context.Background(), h.org.ID, h.device.ID, session.LogEventInput{
		Kind:       model.LogKindConn,
		OccurredAt: h.now.Add(-30 * time.Second),
	})
	require.NoError(t, err)
	require.NotEqual(t, panel.ID, native.ID)

	sess, err := h.svc.RecordLogEvent(context.Background(), h.org.ID, h.device.ID, session.LogEventInput{
		Kind:       model.LogKindError,
		OccurredAt: h.now,
	})
	require.NoError(t, err)
	require.Nil(t, sess, "multiple candidates: no single session to return")

	panelRow := h.reloadSession(t, panel.ID)
	require.NotNil(t, panelRow.LastActivityAt)
	require.Equal(t, h.now.UTC(), panelRow.LastActivityAt.UTC(), "panel candidate is refreshed too")

	nativeRow := h.reloadSession(t, native.ID)
	require.NotNil(t, nativeRow.LastActivityAt)
	require.Equal(t, h.now.UTC(), nativeRow.LastActivityAt.UTC(), "native candidate is refreshed too")

	events := h.sessionEvents(t, native.ID)
	require.Len(t, events, 2)
	require.Equal(t, model.LogKindError, events[1].Kind, "the event is recorded on the native session")
	require.Len(t, h.sessionEvents(t, panel.ID), 1, "the panel keeps only its own connection row")
}

// An activity event with no open session starts a native session: the
// connection was live even though its start was never seen.
func TestRecordLogEvent_ActivityNoCandidateCreatesNative(t *testing.T) {
	h := newHarness(t)

	sess, err := h.svc.RecordLogEvent(context.Background(), h.org.ID, h.device.ID, session.LogEventInput{
		Kind:       model.LogKindFile,
		OccurredAt: h.now,
	})
	require.NoError(t, err)
	require.NotNil(t, sess)
	require.Equal(t, model.SessionOriginNative, sess.Origin)
	require.Equal(t, model.SessionStatusOpen, sess.Status)
}
