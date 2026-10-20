package logcollect

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/device"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// mapStreamer serves one canned batch per container name (once), so the hbbs
// and hbbr tailers of the same organization cannot race for the same lines.
type mapStreamer struct {
	mu     sync.Mutex
	lines  map[string][]string
	served map[string]bool
}

func newMapStreamer(lines map[string][]string) *mapStreamer {
	return &mapStreamer{lines: lines, served: map[string]bool{}}
}

func (m *mapStreamer) Stream(_ context.Context, container string, _ time.Time) (io.ReadCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.served[container] {
		return io.NopCloser(strings.NewReader("")), nil
	}
	m.served[container] = true
	batch := m.lines[container]
	if len(batch) == 0 {
		return io.NopCloser(strings.NewReader("")), nil
	}
	return io.NopCloser(strings.NewReader(strings.Join(batch, "\n") + "\n")), nil
}

// serviceFixture opens an isolated database with one deployed server group per
// organization so the collector's Start picks them up.
func serviceFixture(t *testing.T, orgs ...string) (store.Store, []model.Organization) {
	t.Helper()
	dsn := "file:logcollect_" + sanitizeName(t.Name()) + "?mode=memory&cache=shared"
	st, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	require.NoError(t, st.DB.AutoMigrate(
		&model.Organization{}, &model.User{}, &model.Membership{},
		&model.ServerGroup{}, &model.Device{}, &model.DeviceHeartbeat{},
		&model.LogEvent{},
	))

	created := make([]model.Organization, 0, len(orgs))
	for i, name := range orgs {
		org := model.Organization{Name: name}
		require.NoError(t, st.DB.Create(&org).Error)
		require.NoError(t, st.DB.Create(&model.ServerGroup{
			OrganizationID: org.ID,
			HbbsPort:       uint16(21116 + i*10),
			HbbrPort:       uint16(21117 + i*10),
			State:          model.ServerGroupDeployed,
		}).Error)
		created = append(created, org)
	}
	return *st, created
}

func sanitizeName(name string) string {
	out := make([]rune, 0, len(name))
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}

// A parsed line lands in its own organization only: the scoped query of the
// other org stays empty even though both collectors share one process (C14).
func TestLogEvent_ScopedByOrg(t *testing.T) {
	st, orgs := serviceFixture(t, "org-a", "org-b")
	require.Len(t, orgs, 2)

	parser, err := NewParser(testRules())
	require.NoError(t, err)
	streamer := newMapStreamer(map[string][]string{
		"panel-org-1-hbbs": {
			"2026-10-20T06:00:00.000000001Z INFO connection from 123456789 via 10.0.0.1:1",
		},
	})
	svc := NewService(st.DB, parser, streamer, device.NewService(st.DB, nil),
		Options{InitialBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	svc.Start(ctx)

	// Two tailers per organization (hbbs + hbbr) race for the one batch; wait
	// until at least one event row exists, then stop.
	require.Eventually(t, func() bool {
		var count int64
		require.NoError(t, store.WithoutTenantScope(st.DB).Model(&model.LogEvent{}).Count(&count).Error)
		return count > 0
	}, 3*time.Second, 10*time.Millisecond)
	cancel()
	svc.Wait()

	var all []model.LogEvent
	require.NoError(t, store.WithoutTenantScope(st.DB).Find(&all).Error)
	require.NotEmpty(t, all)
	for _, row := range all {
		require.Equal(t, orgs[0].ID, row.OrganizationID, "only the first org received the batch")
		require.Equal(t, model.LogSourceHbbs, row.Source)
	}

	var otherOrg int64
	require.NoError(t, store.ScopedByOrg(st.DB, orgs[1].ID).
		Model(&model.LogEvent{}).Count(&otherOrg).Error)
	require.Zero(t, otherOrg, "the second organization must see nothing")
}

// A connection line is the auxiliary heartbeat source (C11): the referenced
// device's last_seen_at moves and a heartbeat row is written.
func TestLogActivity_UpdatesHeartbeat(t *testing.T) {
	st, orgs := serviceFixture(t, "org-a")
	org := orgs[0]

	dev, err := device.NewService(st.DB, nil).Register(context.Background(), org.ID, device.RegisterInput{
		Name: "office-pc", RustdeskID: "123456789",
	})
	require.NoError(t, err)
	require.Nil(t, dev.LastSeenAt)

	parser, err := NewParser(testRules())
	require.NoError(t, err)
	// A fresh timestamp: log activity older than the online window is ignored.
	at := time.Now().UTC().Format(time.RFC3339Nano)
	streamer := newMapStreamer(map[string][]string{
		"panel-org-1-hbbs": {at + " INFO connection from 123456789 via 10.0.0.1:1"},
	})
	svc := NewService(st.DB, parser, streamer, device.NewService(st.DB, nil),
		Options{InitialBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	svc.Start(ctx)
	require.Eventually(t, func() bool {
		var row model.Device
		if err := store.ScopedByOrg(st.DB, org.ID).First(&row, dev.ID).Error; err != nil {
			return false
		}
		return row.LastSeenAt != nil
	}, 3*time.Second, 10*time.Millisecond)
	cancel()
	svc.Wait()

	var row model.Device
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).First(&row, dev.ID).Error)
	require.NotNil(t, row.LastSeenAt, "log activity must refresh last_seen_at")

	var beats int64
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).
		Model(&model.DeviceHeartbeat{}).Where("device_id = ?", dev.ID).Count(&beats).Error)
	require.NotZero(t, beats, "the auxiliary source writes a heartbeat row")

	var events int64
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).
		Model(&model.LogEvent{}).Where("device_id = ?", dev.ID).Count(&events).Error)
	require.NotZero(t, events, "the event is associated with the device")
}

// A replayed or backfilled line older than the online window must not
// resurrect a device: the auxiliary source only trusts fresh activity.
func TestLogActivity_StaleLine_Ignored(t *testing.T) {
	st, orgs := serviceFixture(t, "org-a")
	org := orgs[0]
	devices := device.NewService(st.DB, nil)

	dev, err := devices.Register(context.Background(), org.ID, device.RegisterInput{
		Name: "office-pc", RustdeskID: "123456789",
	})
	require.NoError(t, err)

	stale := time.Now().Add(-2 * model.OnlineWindow)
	got, err := devices.RecordLogActivity(context.Background(), org.ID, "123456789", stale)
	require.NoError(t, err)
	require.Nil(t, got, "a stale line is ignored")

	var row model.Device
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).First(&row, dev.ID).Error)
	require.Nil(t, row.LastSeenAt, "stale activity must not move last_seen_at")

	var beats int64
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).
		Model(&model.DeviceHeartbeat{}).Count(&beats).Error)
	require.Zero(t, beats, "stale activity must not write a heartbeat")

	// A fresh line for an unknown device is not an error either.
	got, err = devices.RecordLogActivity(context.Background(), org.ID, "999999999", time.Now())
	require.NoError(t, err)
	require.Nil(t, got)
}

// The startup sweep enforces the documented retention window.
func TestStart_PrunesExpiredEvents(t *testing.T) {
	st, orgs := serviceFixture(t, "org-a")
	org := orgs[0]

	old := model.LogEvent{
		OrganizationID: org.ID, Source: model.LogSourceHbbs,
		Level: model.LogLevelInfo, Kind: model.LogKindConn, DetailJSON: "{}",
		OccurredAt: time.Now().Add(-time.Duration(model.DefaultLogEventRetentionDays+1) * 24 * time.Hour),
	}
	fresh := old
	fresh.OccurredAt = time.Now()
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).Create(&old).Error)
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).Create(&fresh).Error)

	parser, err := NewParser(testRules())
	require.NoError(t, err)
	svc := NewService(st.DB, parser, newMapStreamer(nil), device.NewService(st.DB, nil),
		Options{InitialBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	svc.Start(ctx)
	svc.Unwatch(org.ID)
	cancel()
	svc.Wait()

	var rows []model.LogEvent
	require.NoError(t, store.WithoutTenantScope(st.DB).Find(&rows).Error)
	require.Len(t, rows, 1, "only the expired event is pruned")
	require.True(t, rows[0].OccurredAt.After(time.Now().Add(-time.Hour)))
}

// Unwatch stops the tailers of a deprovisioned organization instead of
// leaving them to poll a container that no longer exists.
func TestWatchUnwatch_StopsTailers(t *testing.T) {
	st, orgs := serviceFixture(t, "org-a")
	org := orgs[0]

	parser, err := NewParser(testRules())
	require.NoError(t, err)
	svc := NewService(st.DB, parser, newMapStreamer(nil), device.NewService(st.DB, nil),
		Options{InitialBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.Start(ctx)

	// Watch is idempotent and Unwatch makes the goroutines exit.
	svc.Watch(org.ID)
	svc.Watch(org.ID)
	svc.Unwatch(org.ID)

	done := make(chan struct{})
	go func() {
		svc.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("tailers did not stop after Unwatch")
	}
}

// A line that was already read must still be persisted when the collector is
// shutting down: the shutdown signal cancels the following context, and an
// event that is parsed but not stored is a silent data loss. This regressed in
// CI under -race, where cancelling the context between the heartbeat refresh
// and the event insert dropped the event entirely.
func TestHandleLine_CancelledContext_StillPersists(t *testing.T) {
	st, orgs := serviceFixture(t, "org-a")
	org := orgs[0]

	dev, err := device.NewService(st.DB, nil).Register(context.Background(), org.ID, device.RegisterInput{
		Name: "office-pc", RustdeskID: "123456789",
	})
	require.NoError(t, err)

	parser, err := NewParser(testRules())
	require.NoError(t, err)
	svc := NewService(st.DB, parser, newMapStreamer(nil), device.NewService(st.DB, nil),
		Options{InitialBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	svc.handleLine(ctx, org.ID, model.LogSourceHbbs,
		"INFO connection from 123456789 via 10.0.0.1:1", time.Now().UTC())

	var events int64
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).
		Model(&model.LogEvent{}).Where("device_id = ?", dev.ID).Count(&events).Error)
	require.NotZero(t, events, "an already-read line must not be lost on shutdown")

	var beats int64
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).
		Model(&model.DeviceHeartbeat{}).Where("device_id = ?", dev.ID).Count(&beats).Error)
	require.NotZero(t, beats, "the auxiliary heartbeat must not be lost either")
}

// docker timestamps may carry an offset, and untimestamped lines fall back to
// the local zone. Rows are always stored as UTC because SQLite orders them as
// text and mixed offsets would break the since filter (see the api handler).
func TestHandleLine_StoresOccurredAtInUTC(t *testing.T) {
	st, orgs := serviceFixture(t, "org-a")
	org := orgs[0]

	parser, err := NewParser(testRules())
	require.NoError(t, err)
	svc := NewService(st.DB, parser, newMapStreamer(nil), nil,
		Options{InitialBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond}, nil)

	at := time.Date(2026, 10, 20, 10, 0, 0, 0, time.FixedZone("CST", 8*3600))
	svc.handleLine(context.Background(), org.ID, model.LogSourceHbbs,
		"INFO connection from 123456789 via 10.0.0.1:1", at)

	var row model.LogEvent
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).First(&row).Error)
	require.Equal(t, time.UTC, row.OccurredAt.Location(), "rows must be stored in UTC")
	require.True(t, row.OccurredAt.Equal(at), "the instant must be preserved")
}

// The persist bound must cover the whole write path, including the device
// lookup that runs before the insert: a query without a context waits for a
// free connection indefinitely (sqlite runs with a single connection), and a
// stuck database would then hold the tailer forever.
func TestHandleLine_DeviceLookupHonoursPersistDeadline(t *testing.T) {
	// A file-backed database: the test holds the only connection for a while,
	// and an in-memory one would be dropped once every connection closes.
	dsn := "file:" + filepath.ToSlash(filepath.Join(t.TempDir(), "lookup.db"))
	st, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	require.NoError(t, st.DB.AutoMigrate(
		&model.Organization{}, &model.Device{}, &model.DeviceHeartbeat{}, &model.LogEvent{},
	))
	org := model.Organization{Name: "org-a"}
	require.NoError(t, st.DB.Create(&org).Error)

	dev, err := device.NewService(st.DB, nil).Register(context.Background(), org.ID, device.RegisterInput{
		Name: "office-pc", RustdeskID: "123456789",
	})
	require.NoError(t, err)

	parser, err := NewParser(testRules())
	require.NoError(t, err)
	svc := NewService(st.DB, parser, newMapStreamer(nil), nil,
		Options{PersistTimeout: 100 * time.Millisecond}, nil)

	// Take the only connection so every further query has to wait for it.
	sqlDB, err := st.DB.DB()
	require.NoError(t, err)
	conn, err := sqlDB.Conn(context.Background())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		svc.handleLine(context.Background(), org.ID, model.LogSourceHbbs,
			"INFO connection from 123456789 via 10.0.0.1:1", time.Now().UTC())
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the device lookup must honour the persist deadline instead of waiting forever")
	}

	// The connection is released again, so a later line still persists.
	require.NoError(t, conn.Close())
	svc.handleLine(context.Background(), org.ID, model.LogSourceHbbs,
		"INFO connection from 123456789 via 10.0.0.1:1", time.Now().UTC())
	var events int64
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).
		Model(&model.LogEvent{}).Where("device_id = ?", dev.ID).Count(&events).Error)
	require.NotZero(t, events, "a later line must still be stored")
}

// A provisioning worker detached with WithoutCancel can notify the collector
// after shutdown started: main is already draining (wg.Wait) while the
// callback calls Watch. Registering a tailer then is a documented WaitGroup
// misuse (Add concurrent with Wait) and the tailer would exit immediately, so
// a cancelled root must make Watch a no-op.
func TestWatch_AfterShutdown_DoesNotRegisterTailers(t *testing.T) {
	st, _ := serviceFixture(t, "org-a")
	parser, err := NewParser(testRules())
	require.NoError(t, err)
	svc := NewService(st.DB, parser, newMapStreamer(nil), nil,
		Options{InitialBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	svc.Start(ctx)
	cancel()
	svc.Wait()

	svc.Watch(9999)

	svc.mu.Lock()
	_, registered := svc.watched[9999]
	svc.mu.Unlock()
	require.False(t, registered, "Watch must not register work after the root context was cancelled")
}

// Rows are stored with UTC occurred_at because SQLite compares the column as
// text; the retention cutoff has to be normalised the same way, otherwise a
// host east of UTC prunes events that are still inside the window (and a host
// west of it keeps them too long).
func TestPruneExpired_ComparesOnUTCTimeline(t *testing.T) {
	st, orgs := serviceFixture(t, "org-a")
	org := orgs[0]

	// 10:00+08:00 is 02:00Z; with the 30 day retention the cutoff is
	// 2026-09-20T02:00:00Z.
	local := time.FixedZone("CST", 8*3600)
	now := time.Date(2026, 10, 20, 10, 0, 0, 0, local)
	cutoff := now.UTC().Add(-time.Duration(model.DefaultLogEventRetentionDays) * 24 * time.Hour)

	keep := model.LogEvent{
		OrganizationID: org.ID, Source: model.LogSourceHbbs, Level: model.LogLevelInfo,
		Kind: model.LogKindConn, DetailJSON: "{}", OccurredAt: cutoff.Add(time.Hour),
	}
	drop := keep
	drop.OccurredAt = cutoff.Add(-time.Hour)
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).Create(&keep).Error)
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).Create(&drop).Error)

	parser, err := NewParser(testRules())
	require.NoError(t, err)
	svc := NewService(st.DB, parser, newMapStreamer(nil), nil, Options{}, nil)
	svc.now = func() time.Time { return now }
	svc.pruneExpired()

	var rows []model.LogEvent
	require.NoError(t, store.WithoutTenantScope(st.DB).Find(&rows).Error)
	require.Len(t, rows, 1, "only the event outside the window is pruned")
	require.True(t, rows[0].OccurredAt.Equal(keep.OccurredAt),
		"the event one hour inside the window must survive")
}

// A provisioning notification can arrive after the organization was
// deprovisioned: the server group row is gone and Unwatch already ran, so a
// late Watch must not resurrect tailers for containers that no longer exist.
func TestWatch_SkipsDeprovisionedOrganization(t *testing.T) {
	st, orgs := serviceFixture(t, "org-a")
	org := orgs[0]
	require.NoError(t, store.WithoutTenantScope(st.DB).
		Where("organization_id = ?", org.ID).Delete(&model.ServerGroup{}).Error)

	parser, err := NewParser(testRules())
	require.NoError(t, err)
	svc := NewService(st.DB, parser, newMapStreamer(nil), nil,
		Options{InitialBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.Start(ctx)
	svc.Watch(org.ID)

	svc.mu.Lock()
	_, registered := svc.watched[org.ID]
	svc.mu.Unlock()
	require.False(t, registered, "a deprovisioned organization must not be watched")

	cancel()
	svc.Wait()
}

// A transient database error must not stop collection. Start and the
// provisioning callback each call Watch once and do not retry, so treating
// "state query failed" as "not deployed" would cancel the tailers until the
// process restarts; only a successful query that finds no deployment may.
func TestWatch_KeepsTailersWhenStateQueryFails(t *testing.T) {
	st, orgs := serviceFixture(t, "org-a")
	org := orgs[0]

	parser, err := NewParser(testRules())
	require.NoError(t, err)
	svc := NewService(st.DB, parser, newMapStreamer(nil), nil,
		Options{InitialBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.Start(ctx)

	// Force the state lookup to fail, then re-register the organization.
	svc.Unwatch(org.ID)
	require.NoError(t, st.Close())
	svc.Watch(org.ID)

	svc.mu.Lock()
	_, registered := svc.watched[org.ID]
	svc.mu.Unlock()
	require.True(t, registered, "a failed state query must not cancel collection")

	cancel()
	svc.Wait()
}
