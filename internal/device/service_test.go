package device_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/device"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

const (
	maxNameLenForTest    = 128
	maxRustdeskIDForTest = 64
)

type fixture struct {
	svc  *device.Service
	st   store.Store
	orgA model.Organization
	orgB model.Organization
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dsn := fmt.Sprintf("file:dev_%d?mode=memory&cache=shared", time.Now().UnixNano())
	st, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	require.NoError(t, st.DB.AutoMigrate(
		&model.Organization{}, &model.Device{}, &model.DeviceHeartbeat{},
	))

	orgA := model.Organization{Name: "org-a"}
	orgB := model.Organization{Name: "org-b"}
	require.NoError(t, st.DB.Create(&orgA).Error)
	require.NoError(t, st.DB.Create(&orgB).Error)

	return &fixture{
		svc:  device.NewService(st.DB, nil),
		st:   *st,
		orgA: orgA,
		orgB: orgB,
	}
}

func TestRegister_SameFingerprint_Upserts(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	first, err := f.svc.Register(ctx, f.orgA.ID, device.RegisterInput{Name: "laptop", RustdeskID: "123456789"})
	require.NoError(t, err)

	second, err := f.svc.Register(ctx, f.orgA.ID, device.RegisterInput{Name: "laptop-renamed", RustdeskID: "123456789"})
	require.NoError(t, err)

	require.Equal(t, first.ID, second.ID, "same rustdesk id must update the existing row")
	require.Equal(t, "laptop-renamed", second.Name)

	var count int64
	require.NoError(t, store.ScopedByOrg(f.st.DB, f.orgA.ID).Model(&model.Device{}).Count(&count).Error)
	require.EqualValues(t, 1, count)
}

func TestTenantIsolation_Devices(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	_, err := f.svc.Register(ctx, f.orgA.ID, device.RegisterInput{Name: "a-device", RustdeskID: "shared-id"})
	require.NoError(t, err)
	_, err = f.svc.Register(ctx, f.orgB.ID, device.RegisterInput{Name: "b-device", RustdeskID: "shared-id"})
	require.NoError(t, err, "the same rustdesk id may exist in another org")

	var orgADevices []model.Device
	require.NoError(t, store.ScopedByOrg(f.st.DB, f.orgA.ID).Find(&orgADevices).Error)
	require.Len(t, orgADevices, 1)
	require.Equal(t, "a-device", orgADevices[0].Name)

	// Heartbeating another org's device must not find it.
	_, err = f.svc.Heartbeat(ctx, f.orgB.ID, orgADevices[0].ID)
	require.ErrorIs(t, err, device.ErrDeviceNotFound)
}

func TestOnline_WindowEdge(t *testing.T) {
	now := time.Now()
	recent := now.Add(-89 * time.Second)
	stale := now.Add(-91 * time.Second)

	require.True(t, (&model.Device{LastSeenAt: &recent}).Online(now), "89s old heartbeat is online")
	require.False(t, (&model.Device{LastSeenAt: &stale}).Online(now), "91s old heartbeat is offline")
	require.False(t, (&model.Device{}).Online(now), "a device without heartbeat is offline")
	require.Equal(t, "online", device.Status(&model.Device{LastSeenAt: &recent}, now))
	require.Equal(t, "offline", device.Status(&model.Device{LastSeenAt: &stale}, now))
}

func TestHeartbeat_UpdatesLastSeenAndRecordsEvent(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	dev, err := f.svc.Register(ctx, f.orgA.ID, device.RegisterInput{Name: "pc", RustdeskID: "987654321"})
	require.NoError(t, err)
	require.Nil(t, dev.LastSeenAt)

	updated, err := f.svc.Heartbeat(ctx, f.orgA.ID, dev.ID)
	require.NoError(t, err)
	require.NotNil(t, updated.LastSeenAt)

	var beats int64
	require.NoError(t, store.ScopedByOrg(f.st.DB, f.orgA.ID).Model(&model.DeviceHeartbeat{}).Count(&beats).Error)
	require.EqualValues(t, 1, beats)
}

func TestRegister_RequiresOrg(t *testing.T) {
	f := newFixture(t)
	_, err := f.svc.Register(context.Background(), 0, device.RegisterInput{Name: "x", RustdeskID: "y"})
	require.Error(t, err)
	require.False(t, errors.Is(err, device.ErrDeviceNotFound))
}

func TestRegister_RejectsOversizedFields(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	_, err := f.svc.Register(ctx, f.orgA.ID, device.RegisterInput{
		Name:       strings.Repeat("n", maxNameLenForTest+1),
		RustdeskID: "id-1",
	})
	require.ErrorIs(t, err, device.ErrInvalidInput)

	_, err = f.svc.Register(ctx, f.orgA.ID, device.RegisterInput{
		Name:       "ok",
		RustdeskID: strings.Repeat("9", maxRustdeskIDForTest+1),
	})
	require.ErrorIs(t, err, device.ErrInvalidInput)
}

func TestHeartbeat_NeverMovesLastSeenBackwards(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	dev, err := f.svc.Register(ctx, f.orgA.ID, device.RegisterInput{Name: "pc", RustdeskID: "clock-1"})
	require.NoError(t, err)

	later := time.Now()
	f.svc = device.NewService(f.st.DB, func() time.Time { return later })
	_, err = f.svc.Heartbeat(ctx, f.orgA.ID, dev.ID)
	require.NoError(t, err)

	// A heartbeat that started earlier but finishes later must not regress.
	earlier := later.Add(-30 * time.Second)
	f.svc = device.NewService(f.st.DB, func() time.Time { return earlier })
	after, err := f.svc.Heartbeat(ctx, f.orgA.ID, dev.ID)
	require.NoError(t, err)
	require.NotNil(t, after.LastSeenAt)
	require.WithinDuration(t, later, *after.LastSeenAt, time.Second)

	var beats int64
	require.NoError(t, store.ScopedByOrg(f.st.DB, f.orgA.ID).Model(&model.DeviceHeartbeat{}).Count(&beats).Error)
	require.EqualValues(t, 2, beats, "every heartbeat event is still recorded")
}

func TestOnline_FutureTimestampIsOffline(t *testing.T) {
	now := time.Now()
	future := now.Add(2 * time.Minute)
	require.False(t, (&model.Device{LastSeenAt: &future}).Online(now), "a far-future heartbeat must not count as online")

	slightFuture := now.Add(2 * time.Second)
	require.True(t, (&model.Device{LastSeenAt: &slightFuture}).Online(now), "small clock skew stays online")
}

// Client heartbeats and log-derived heartbeats must stay distinguishable:
// DeviceHeartbeat.Source records the provenance, so the auxiliary source (C11)
// is not reported as if the client had checked in.
func TestHeartbeat_SourceDistinguishesClientFromLog(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	dev, err := f.svc.Register(ctx, f.orgA.ID, device.RegisterInput{Name: "pc", RustdeskID: "987654321"})
	require.NoError(t, err)

	// Log activity first: the auxiliary source is deduplicated within 30s, so
	// a client report has to follow it to get its own row.
	_, err = f.svc.RecordLogActivity(ctx, f.orgA.ID, dev.RustdeskID, time.Now())
	require.NoError(t, err)
	_, err = f.svc.Heartbeat(ctx, f.orgA.ID, dev.ID)
	require.NoError(t, err)

	var sources []string
	require.NoError(t, store.ScopedByOrg(f.st.DB, f.orgA.ID).
		Model(&model.DeviceHeartbeat{}).Order("id").Pluck("source", &sources).Error)
	require.Equal(t, []string{"log", "api"}, sources)
}
