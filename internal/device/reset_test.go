package device_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/device"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

type fakeRecorder struct {
	mu      sync.Mutex
	entries []audit.Entry
	fail    error
}

func (f *fakeRecorder) RecordTx(_ *gorm.DB, e audit.Entry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	f.entries = append(f.entries, e)
	return nil
}

func (f *fakeRecorder) actions() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.entries))
	for _, e := range f.entries {
		out = append(out, e.Action)
	}
	return out
}

func (f *fakeRecorder) recorded() []audit.Entry {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]audit.Entry(nil), f.entries...)
}

func newResetFixture(t *testing.T) (*store.Store, *device.Service, *fakeRecorder, model.Organization) {
	t.Helper()
	st := openDeviceStore(t)
	t.Cleanup(func() { _ = st.Close() })
	require.NoError(t, st.DB.AutoMigrate(
		&model.Organization{}, &model.Device{}, &model.DeviceHeartbeat{},
	))
	org := model.Organization{Name: "reset-org"}
	require.NoError(t, st.DB.Create(&org).Error)
	recorder := &fakeRecorder{}
	return st, device.NewService(st.DB, recorder, nil), recorder, org
}

func TestResetBinding_ClearsAndBumps(t *testing.T) {
	st, svc, recorder, org := newResetFixture(t)
	ctx := context.Background()

	dev := seedDevice(t, st, org.ID, "1001", "workstation", "old-uuid")
	require.EqualValues(t, 1, dev.BindingGeneration)

	updated, err := svc.ResetBinding(ctx, org.ID, dev.ID, 7, "员工换机")
	require.NoError(t, err)
	require.Equal(t, "", updated.BoundUUID)
	require.EqualValues(t, 2, updated.BindingGeneration)

	entries := recorder.recorded()
	require.Len(t, entries, 1)
	e := entries[0]
	require.Equal(t, "device.binding.reset", e.Action)
	require.EqualValues(t, org.ID, e.OrganizationID)
	require.EqualValues(t, 7, e.ActorUserID)
	require.Equal(t, "device", e.TargetType)
	require.Equal(t, fmt.Sprint(dev.ID), e.TargetID)
	require.Equal(t, "员工换机", e.Detail["reason"])
	require.Equal(t, true, e.Detail["had_binding"])
	require.Equal(t, dev.RustdeskID, e.Detail["rustdesk_id"])
}

func TestResetBinding_UnboundStillBumps(t *testing.T) {
	st, svc, recorder, org := newResetFixture(t)
	ctx := context.Background()

	dev := seedDevice(t, st, org.ID, "1001", "unbound", "")
	require.EqualValues(t, 0, dev.BindingGeneration)

	updated, err := svc.ResetBinding(ctx, org.ID, dev.ID, 7, "预置清理")
	require.NoError(t, err)
	require.EqualValues(t, 1, updated.BindingGeneration, "every reset invalidates prior snapshots")

	entries := recorder.recorded()
	require.Len(t, entries, 1)
	require.Equal(t, false, entries[0].Detail["had_binding"])
}

func TestResetBinding_DoubleResetBumpsTwice(t *testing.T) {
	st, svc, recorder, org := newResetFixture(t)
	ctx := context.Background()

	dev := seedDevice(t, st, org.ID, "1001", "workstation", "old-uuid")

	_, err := svc.ResetBinding(ctx, org.ID, dev.ID, 7, "第一次")
	require.NoError(t, err)
	second, err := svc.ResetBinding(ctx, org.ID, dev.ID, 7, "第二次")
	require.NoError(t, err, "a second reset must stay a success")
	require.EqualValues(t, 3, second.BindingGeneration)
	require.Len(t, recorder.actions(), 2)
}

func TestResetBinding_NotFoundIsCrossTenant(t *testing.T) {
	st, svc, recorder, org := newResetFixture(t)
	ctx := context.Background()

	other := model.Organization{Name: "other-reset-org"}
	require.NoError(t, st.DB.Create(&other).Error)
	dev := seedDevice(t, st, org.ID, "1001", "workstation", "old-uuid")

	_, err := svc.ResetBinding(ctx, other.ID, dev.ID, 7, "越权尝试")
	require.ErrorIs(t, err, device.ErrDeviceNotFound)
	require.Empty(t, recorder.recorded(), "a rejected reset must not audit")

	// The row is untouched.
	var stored model.Device
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).First(&stored, dev.ID).Error)
	require.Equal(t, "old-uuid", stored.BoundUUID)
	require.EqualValues(t, 1, stored.BindingGeneration)
}

func TestResetBinding_ReasonValidation(t *testing.T) {
	st, svc, recorder, org := newResetFixture(t)
	ctx := context.Background()

	dev := seedDevice(t, st, org.ID, "1001", "workstation", "old-uuid")

	for _, reason := range []string{"", "   ", strings.Repeat("换", 501)} {
		_, err := svc.ResetBinding(ctx, org.ID, dev.ID, 7, reason)
		require.ErrorIs(t, err, device.ErrInvalidInput, "reason %q must be rejected", reason)
	}
	require.Empty(t, recorder.recorded(), "invalid input must not audit")

	updated, err := svc.ResetBinding(ctx, org.ID, dev.ID, 7, strings.Repeat("换", 500))
	require.NoError(t, err, "500 runes is within the contract bound")
	require.EqualValues(t, 2, updated.BindingGeneration)
}

func TestResetBinding_AuditFailureRollsBack(t *testing.T) {
	st, svc, recorder, org := newResetFixture(t)
	ctx := context.Background()

	dev := seedDevice(t, st, org.ID, "1001", "workstation", "old-uuid")
	recorder.fail = errors.New("audit down")

	_, err := svc.ResetBinding(ctx, org.ID, dev.ID, 7, "员工换机")
	require.Error(t, err)

	var stored model.Device
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).First(&stored, dev.ID).Error)
	require.Equal(t, "old-uuid", stored.BoundUUID, "the binding must survive an unaudited reset")
	require.EqualValues(t, 1, stored.BindingGeneration)
}

func TestResetBinding_NoRecorderFailsClosed(t *testing.T) {
	st, _, _, org := newResetFixture(t)
	ctx := context.Background()

	dev := seedDevice(t, st, org.ID, "1001", "workstation", "old-uuid")
	svc := device.NewService(st.DB, nil, nil)

	_, err := svc.ResetBinding(ctx, org.ID, dev.ID, 7, "员工换机")
	require.Error(t, err)
	require.Contains(t, err.Error(), "no audit recorder")

	var stored model.Device
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).First(&stored, dev.ID).Error)
	require.Equal(t, "old-uuid", stored.BoundUUID)
	require.EqualValues(t, 1, stored.BindingGeneration)
}
