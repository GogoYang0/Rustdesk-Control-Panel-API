package strategy_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/strategy"
)

func TestDisconnect_RequestCreatesPendingAndAudits(t *testing.T) {
	f := newFixture(t)
	req, err := f.svc.RequestDisconnect(context.Background(), f.org.ID, f.user.ID, f.device.ID, "offboarding")
	require.NoError(t, err)
	require.Equal(t, model.DisconnectStatusPending, req.Status)
	require.Equal(t, "offboarding", req.Reason)
	require.Equal(t, f.user.ID, req.RequestedBy)
	require.WithinDuration(t, f.now.Add(strategy.DisconnectTTL), req.ExpiresAt, time.Second)
	require.Equal(t, []string{"device.disconnect.request"}, f.recorder.actions())
}

func TestDisconnect_DuplicatePendingConflicts(t *testing.T) {
	f := newFixture(t)
	_, err := f.svc.RequestDisconnect(context.Background(), f.org.ID, f.user.ID, f.device.ID, "first")
	require.NoError(t, err)

	// A second request would stack up and fire a second teardown on the same
	// connection set; the client only needs one.
	_, err = f.svc.RequestDisconnect(context.Background(), f.org.ID, f.user.ID, f.device.ID, "second")
	require.ErrorIs(t, err, strategy.ErrDisconnectPending)
}

func TestDisconnect_EmptyReasonRejected(t *testing.T) {
	f := newFixture(t)
	_, err := f.svc.RequestDisconnect(context.Background(), f.org.ID, f.user.ID, f.device.ID, "   ")
	require.ErrorIs(t, err, strategy.ErrInvalidReason)
}

func TestDisconnect_CrossOrgDeviceIsNotFound(t *testing.T) {
	f := newFixture(t)
	foreign := model.Device{OrganizationID: f.otherOrg.ID, RustdeskID: "foreign-x", Name: "x"}
	require.NoError(t, store.ScopedByOrg(f.db, f.otherOrg.ID).Create(&foreign).Error)

	_, err := f.svc.RequestDisconnect(context.Background(), f.org.ID, f.user.ID, foreign.ID, "nope")
	require.ErrorIs(t, err, strategy.ErrNotFound)
}

// TestDisconnect_TakeConsumesWithConns is the core of D4: the request is
// fulfilled only by a heartbeat that reports live connections, and only those
// connection ids are returned.
func TestDisconnect_TakeConsumesWithConns(t *testing.T) {
	f := newFixture(t)
	_, err := f.svc.RequestDisconnect(context.Background(), f.org.ID, f.user.ID, f.device.ID, "leak")
	require.NoError(t, err)
	f.recorder.entries = nil

	err = f.db.Transaction(func(tx *gorm.DB) error {
		conns, terr := f.svc.TakePendingTx(tx, f.org.ID, f.device.ID, []int64{11, 12})
		require.NoError(t, terr)
		require.Equal(t, []int64{11, 12}, conns)
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, []string{"device.disconnect.fulfilled"}, f.recorder.actions())

	var rows []model.DeviceDisconnect
	require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).Find(&rows).Error)
	require.Len(t, rows, 1)
	require.Equal(t, model.DisconnectStatusFulfilled, rows[0].Status)
	require.NotNil(t, rows[0].FulfilledAt)
	require.Equal(t, 2, rows[0].ConnCount)

	// Consumed once: a second heartbeat must not repeat the teardown.
	require.NoError(t, f.db.Transaction(func(tx *gorm.DB) error {
		conns, terr := f.svc.TakePendingTx(tx, f.org.ID, f.device.ID, []int64{11, 12})
		require.NoError(t, terr)
		require.Empty(t, conns)
		return nil
	}))
}

// TestDisconnect_NoConnsKeepsPending: a heartbeat without live connections
// must not burn the request — the client simply had nothing to drop.
func TestDisconnect_NoConnsKeepsPending(t *testing.T) {
	f := newFixture(t)
	_, err := f.svc.RequestDisconnect(context.Background(), f.org.ID, f.user.ID, f.device.ID, "later")
	require.NoError(t, err)

	require.NoError(t, f.db.Transaction(func(tx *gorm.DB) error {
		conns, terr := f.svc.TakePendingTx(tx, f.org.ID, f.device.ID, nil)
		require.NoError(t, terr)
		require.Empty(t, conns)
		return nil
	}))

	var row model.DeviceDisconnect
	require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).First(&row).Error)
	require.Equal(t, model.DisconnectStatusPending, row.Status)
}

func TestDisconnect_ExpireStale(t *testing.T) {
	f := newFixture(t)
	_, err := f.svc.RequestDisconnect(context.Background(), f.org.ID, f.user.ID, f.device.ID, "old")
	require.NoError(t, err)
	f.recorder.entries = nil

	// Not yet due: nothing happens.
	n, err := f.svc.ExpireStale(context.Background(), f.now.Add(time.Minute))
	require.NoError(t, err)
	require.Zero(t, n)

	// Past the TTL: marked expired and audited as a system action.
	n, err = f.svc.ExpireStale(context.Background(), f.now.Add(strategy.DisconnectTTL+time.Minute))
	require.NoError(t, err)
	require.EqualValues(t, 1, n)

	var row model.DeviceDisconnect
	require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).First(&row).Error)
	require.Equal(t, model.DisconnectStatusExpired, row.Status)
	require.Equal(t, []string{"device.disconnect.expired"}, f.recorder.actions())
	require.Zero(t, f.recorder.entries[0].ActorUserID, "expiry is a system action, not a person's")
}

// TestDisconnect_NoteConnsRecordsLatestHeartbeat pins the informational column:
// the connection ids the client reported are kept on the newest heartbeat row.
func TestDisconnect_NoteConnsRecordsLatestHeartbeat(t *testing.T) {
	f := newFixture(t)
	require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).Create(&model.DeviceHeartbeat{
		OrganizationID: f.org.ID, DeviceID: f.device.ID, At: f.now, Source: "api",
	}).Error)

	require.NoError(t, f.svc.NoteConns(context.Background(), f.org.ID, f.device.ID, []int64{7, 8}))

	var hb model.DeviceHeartbeat
	require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).First(&hb).Error)
	require.JSONEq(t, "[7,8]", hb.ConnIDs)
}
