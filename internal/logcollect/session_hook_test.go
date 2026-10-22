package logcollect

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/device"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

type recordingSessions struct {
	events []hookEvent
	panic_ bool
}

type hookEvent struct {
	orgID    uint
	deviceID uint
	kind     string
	at       time.Time
}

func (r *recordingSessions) RecordLogEvent(ctx context.Context, orgID, deviceID uint, kind string, at time.Time, detail map[string]any) error {
	if r.panic_ {
		panic("hook exploded")
	}
	r.events = append(r.events, hookEvent{orgID: orgID, deviceID: deviceID, kind: kind, at: at})
	return nil
}

func sessionHookFixture(t *testing.T, hook SessionRecorder, line string) (*Service, *store.Store, *device.Service, *model.Device) {
	t.Helper()
	stv, orgs := serviceFixture(t, "hook-org")
	st := &stv
	org := orgs[0]
	devices := device.NewService(st.DB, nil)
	dev, err := devices.Register(context.Background(), org.ID, device.RegisterInput{
		Name: "office-pc", RustdeskID: "123456789",
	})
	require.NoError(t, err)
	parser, err := NewParser(testRules())
	require.NoError(t, err)
	streamer := newMapStreamer(map[string][]string{
		"panel-org-" + strconv.Itoa(int(org.ID)) + "-hbbs": {line},
	})
	svc := NewService(st.DB, parser, streamer, devices,
		Options{InitialBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond, Sessions: hook}, nil)
	return svc, st, devices, dev
}

func waitStored(t *testing.T, st *store.Store) {
	t.Helper()
	require.Eventually(t, func() bool {
		var count int64
		require.NoError(t, store.WithoutTenantScope(st.DB).Model(&model.LogEvent{}).Count(&count).Error)
		return count > 0
	}, 3*time.Second, 10*time.Millisecond)
}

// The collector hands every device-associated event to the session tracker
// after the row is stored.
func TestSessionHook_ReceivesConnEvent(t *testing.T) {
	hook := &recordingSessions{}
	svc, st, _, dev := sessionHookFixture(t, hook,
		"INFO connection from 123456789 via 10.0.0.1:1")

	ctx, cancel := context.WithCancel(context.Background())
	svc.Start(ctx)
	waitStored(t, st)
	cancel()
	svc.Wait()

	require.NotEmpty(t, hook.events)
	ev := hook.events[0]
	require.Equal(t, dev.OrganizationID, ev.orgID)
	require.Equal(t, dev.ID, ev.deviceID)
	require.Equal(t, model.LogKindConn, ev.kind)
}

// A panicking hook must not kill the tailer or lose the event: session
// tracking is a consumer of the log, never a dependency (C7).
func TestSessionHook_PanicDoesNotBreakStorage(t *testing.T) {
	hook := &recordingSessions{panic_: true}
	svc, st, _, _ := sessionHookFixture(t, hook,
		"INFO connection from 123456789 via 10.0.0.1:1")

	ctx, cancel := context.WithCancel(context.Background())
	svc.Start(ctx)
	waitStored(t, st)
	cancel()
	svc.Wait()

	var count int64
	require.NoError(t, store.WithoutTenantScope(st.DB).Model(&model.LogEvent{}).Count(&count).Error)
	require.Positive(t, count, "the event is stored even though the hook exploded")
}

// Lines without a device reference carry no session semantics.
func TestSessionHook_SkipsUnassociatedLines(t *testing.T) {
	hook := &recordingSessions{}
	svc, st, _, _ := sessionHookFixture(t, hook,
		"ERROR something unrelated happened")

	ctx, cancel := context.WithCancel(context.Background())
	svc.Start(ctx)
	waitStored(t, st)
	cancel()
	svc.Wait()

	require.Empty(t, hook.events, "no device, no session event")
}
