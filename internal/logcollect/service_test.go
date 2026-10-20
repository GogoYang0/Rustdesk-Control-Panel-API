package logcollect

import (
	"context"
	"io"
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
