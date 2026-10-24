package device_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/device"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func newDisableFixture(t *testing.T) (*store.Store, *device.Service, *fakeRecorder, model.Organization) {
	t.Helper()
	st := openDeviceStore(t)
	t.Cleanup(func() { _ = st.Close() })
	require.NoError(t, st.DB.AutoMigrate(
		&model.Organization{}, &model.Device{}, &model.DeviceHeartbeat{},
		&model.CompatSession{},
	))
	org := model.Organization{Name: "disable-org"}
	require.NoError(t, st.DB.Create(&org).Error)
	recorder := &fakeRecorder{}
	return st, device.NewService(st.DB, recorder, nil), recorder, org
}

func seedDeviceSession(t *testing.T, st *store.Store, orgID, userID uint, rustdeskID, jti string) model.CompatSession {
	t.Helper()
	row := model.CompatSession{
		OrganizationID: orgID,
		UserID:         userID,
		JTI:            jti,
		DeviceID:       rustdeskID,
		UUID:           "uuid-disable",
		ExpiresAt:      time.Now().Add(time.Hour),
	}
	require.NoError(t, store.ScopedByOrg(st.DB, orgID).Create(&row).Error)
	return row
}

func TestSetDisabled_DisablesRevokesSessionsAndAudits(t *testing.T) {
	st, svc, recorder, org := newDisableFixture(t)
	ctx := context.Background()

	dev := seedDevice(t, st, org.ID, "1001", "workstation", "uuid-disable")
	sess := seedDeviceSession(t, st, org.ID, 9, dev.RustdeskID, "jti-disable")

	updated, err := svc.SetDisabled(ctx, org.ID, dev.ID, 7, true)
	require.NoError(t, err)
	require.True(t, updated.Disabled)
	require.NotNil(t, updated.DisabledAt)
	require.EqualValues(t, 7, updated.DisabledBy)

	var stored model.CompatSession
	require.NoError(t, store.WithoutTenantScope(st.DB).First(&stored, sess.ID).Error)
	require.NotNil(t, stored.RevokedAt, "disabling a device must revoke its compat sessions")

	entries := recorder.recorded()
	require.Len(t, entries, 1)
	e := entries[0]
	require.Equal(t, "device.disable", e.Action)
	require.EqualValues(t, org.ID, e.OrganizationID)
	require.EqualValues(t, 7, e.ActorUserID)
	require.Equal(t, "device", e.TargetType)
	require.Equal(t, fmt.Sprint(dev.ID), e.TargetID)
	require.Equal(t, dev.RustdeskID, e.Detail["rustdesk_id"])
	require.EqualValues(t, 1, e.Detail["revoked_sessions"])

	// Re-enabling clears the flags and audits the restore; the revoked session
	// stays dead, the client must log in again.
	restored, err := svc.SetDisabled(ctx, org.ID, dev.ID, 7, false)
	require.NoError(t, err)
	require.False(t, restored.Disabled)
	require.Nil(t, restored.DisabledAt)
	require.Zero(t, restored.DisabledBy)
	require.Equal(t, []string{"device.disable", "device.enable"}, recorder.actions())
}

func TestSetDisabled_RepeatIsNoOp(t *testing.T) {
	st, svc, recorder, org := newDisableFixture(t)
	ctx := context.Background()
	dev := seedDevice(t, st, org.ID, "1001", "workstation", "")

	_, err := svc.SetDisabled(ctx, org.ID, dev.ID, 7, true)
	require.NoError(t, err)
	again, err := svc.SetDisabled(ctx, org.ID, dev.ID, 7, true)
	require.NoError(t, err)
	require.True(t, again.Disabled)
	require.Len(t, recorder.actions(), 1, "repeating the state must not add an audit row")
}

func TestSetDisabled_CrossTenantNotFound(t *testing.T) {
	st, svc, recorder, org := newDisableFixture(t)
	ctx := context.Background()
	other := model.Organization{Name: "other-disable-org"}
	require.NoError(t, st.DB.Create(&other).Error)
	dev := seedDevice(t, st, org.ID, "1001", "workstation", "")

	_, err := svc.SetDisabled(ctx, other.ID, dev.ID, 7, true)
	require.ErrorIs(t, err, device.ErrDeviceNotFound)
	require.Empty(t, recorder.recorded())

	var stored model.Device
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).First(&stored, dev.ID).Error)
	require.False(t, stored.Disabled)
}

func TestSetDisabled_AuditFailureRollsBack(t *testing.T) {
	st, svc, recorder, org := newDisableFixture(t)
	ctx := context.Background()
	dev := seedDevice(t, st, org.ID, "1001", "workstation", "uuid-disable")
	sess := seedDeviceSession(t, st, org.ID, 9, dev.RustdeskID, "jti-disable")
	recorder.fail = errors.New("audit down")

	_, err := svc.SetDisabled(ctx, org.ID, dev.ID, 7, true)
	require.Error(t, err)

	var stored model.Device
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).First(&stored, dev.ID).Error)
	require.False(t, stored.Disabled, "the device must stay enabled without its audit row")

	var storedSession model.CompatSession
	require.NoError(t, store.WithoutTenantScope(st.DB).First(&storedSession, sess.ID).Error)
	require.Nil(t, storedSession.RevokedAt)
}

func TestSetDisabled_NoRecorderFailsClosed(t *testing.T) {
	st, _, _, org := newDisableFixture(t)
	ctx := context.Background()
	dev := seedDevice(t, st, org.ID, "1001", "workstation", "")
	svc := device.NewService(st.DB, nil, nil)

	_, err := svc.SetDisabled(ctx, org.ID, dev.ID, 7, true)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no audit recorder")

	var stored model.Device
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).First(&stored, dev.ID).Error)
	require.False(t, stored.Disabled)
}
