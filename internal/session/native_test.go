package session_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/session"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

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
