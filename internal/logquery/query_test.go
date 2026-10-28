package logquery_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/logquery"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func (f *fixture) addDevice(t *testing.T, rustdeskID string, owner uint) model.Device {
	t.Helper()
	dev := model.Device{
		OrganizationID: f.org.ID,
		RustdeskID:     rustdeskID + "-" + f.base,
		Name:           rustdeskID,
		BoundUUID:      "uuid-" + rustdeskID,
		OwnerUserID:    &owner,
	}
	require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).Create(&dev).Error)
	return dev
}

func (f *fixture) addConnLog(t *testing.T, dev model.Device, connID int64, started time.Time) {
	t.Helper()
	require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).Create(&model.ConnectionLog{
		OrganizationID: f.org.ID,
		DeviceID:       dev.ID,
		RustdeskID:     dev.RustdeskID,
		ConnID:         connID,
		SessionID:      connID,
		Status:         model.ConnectionLogStatusOpen,
		StartedAt:      started,
		CreatedAt:      started,
		UpdatedAt:      started,
	}).Error)
}

func (f *fixture) addFileLog(t *testing.T, dev model.Device, created time.Time) {
	t.Helper()
	require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).Create(&model.FileLog{
		OrganizationID: f.org.ID,
		DeviceID:       dev.ID,
		RustdeskID:     dev.RustdeskID,
		Direction:      "send",
		FilesJSON:      "[]",
		CreatedAt:      created,
	}).Error)
}

func TestConnections_IndividualScopeOnlyOwnDevices(t *testing.T) {
	f := newFixture(t)
	svc := logquery.NewService(f.db)
	own := f.addDevice(t, "700001", 11)
	other := f.addDevice(t, "700002", 22)
	f.addConnLog(t, own, 1, f.now)
	f.addConnLog(t, other, 2, f.now)

	rows, total, err := svc.Connections(context.Background(), f.org.ID,
		audit.Viewer{Scope: model.AuditScopeIndividual, UserID: 11},
		logquery.Filter{}, 1, 50)
	require.NoError(t, err)
	require.EqualValues(t, 1, total)
	require.Len(t, rows, 1)
	require.Equal(t, own.ID, rows[0].DeviceID)

	// A zero user id must not degrade into a global read.
	rows, total, err = svc.Connections(context.Background(), f.org.ID,
		audit.Viewer{Scope: model.AuditScopeIndividual, UserID: 0},
		logquery.Filter{}, 1, 50)
	require.NoError(t, err)
	require.Zero(t, total)
	require.Empty(t, rows)
}

func TestConnections_GlobalScopeSeesAll(t *testing.T) {
	f := newFixture(t)
	svc := logquery.NewService(f.db)
	first := f.addDevice(t, "700001", 11)
	second := f.addDevice(t, "700002", 22)
	f.addConnLog(t, first, 1, f.now)
	f.addConnLog(t, second, 2, f.now)

	rows, total, err := svc.Connections(context.Background(), f.org.ID,
		audit.Viewer{Scope: model.AuditScopeGlobal, UserID: 11},
		logquery.Filter{}, 1, 50)
	require.NoError(t, err)
	require.EqualValues(t, 2, total)
	require.Len(t, rows, 2)
}

func TestConnections_FiltersByDeviceAndTime(t *testing.T) {
	f := newFixture(t)
	svc := logquery.NewService(f.db)
	dev := f.addDevice(t, "700001", 11)
	f.addConnLog(t, dev, 1, f.now.Add(-2*time.Hour))
	f.addConnLog(t, dev, 2, f.now)

	from := f.now.Add(-time.Hour)
	rows, total, err := svc.Connections(context.Background(), f.org.ID,
		audit.Viewer{Scope: model.AuditScopeGlobal},
		logquery.Filter{DeviceID: &dev.ID, From: &from}, 1, 50)
	require.NoError(t, err)
	require.EqualValues(t, 1, total)
	require.Equal(t, int64(2), rows[0].ConnID)

	rows, total, err = svc.Connections(context.Background(), f.org.ID,
		audit.Viewer{Scope: model.AuditScopeGlobal},
		logquery.Filter{RustdeskID: dev.RustdeskID}, 1, 50)
	require.NoError(t, err)
	require.EqualValues(t, 2, total)
	require.Len(t, rows, 2)
}

func TestExport_CapsAt1000Rows(t *testing.T) {
	f := newFixture(t)
	svc := logquery.NewService(f.db)
	dev := f.addDevice(t, "700001", 11)
	for i := 0; i < 1005; i++ {
		require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).Create(&model.ConnectionLog{
			OrganizationID: f.org.ID,
			DeviceID:       dev.ID,
			RustdeskID:     dev.RustdeskID,
			ConnID:         int64(i + 1),
			SessionID:      int64(i + 1),
			Status:         model.ConnectionLogStatusClosed,
			StartedAt:      f.now,
			CreatedAt:      f.now,
			UpdatedAt:      f.now,
		}).Error)
	}
	rows, err := svc.ExportConnections(context.Background(), f.org.ID,
		audit.Viewer{Scope: model.AuditScopeGlobal}, logquery.Filter{})
	require.NoError(t, err)
	require.Len(t, rows, logquery.ExportLimit)
	require.Equal(t, 1000, logquery.ExportLimit)
}

func TestFileLogs_IndividualScopeOnlyOwnDevices(t *testing.T) {
	f := newFixture(t)
	svc := logquery.NewService(f.db)
	own := f.addDevice(t, "700001", 11)
	other := f.addDevice(t, "700002", 22)
	f.addFileLog(t, own, f.now)
	f.addFileLog(t, other, f.now)

	rows, total, err := svc.FileLogs(context.Background(), f.org.ID,
		audit.Viewer{Scope: model.AuditScopeIndividual, UserID: 11},
		logquery.Filter{}, 1, 50)
	require.NoError(t, err)
	require.EqualValues(t, 1, total)
	require.Equal(t, own.ID, rows[0].DeviceID)

	exported, err := svc.ExportFileLogs(context.Background(), f.org.ID,
		audit.Viewer{Scope: model.AuditScopeIndividual, UserID: 11}, logquery.Filter{})
	require.NoError(t, err)
	require.Len(t, exported, 1)
	require.Equal(t, own.ID, exported[0].DeviceID)
}

func TestPrune_RespectsPerOrgRetention(t *testing.T) {
	f := newFixture(t)
	dev := f.addDevice(t, "700001", 11)
	old := f.now.Add(-40 * 24 * time.Hour)
	f.addConnLog(t, dev, 1, old)
	f.addConnLog(t, dev, 2, f.now)
	f.addFileLog(t, dev, old)
	f.addFileLog(t, dev, f.now)

	// Zero days = keep forever.
	require.NoError(t, f.db.Model(&model.Organization{}).Where("id = ?", f.org.ID).
		Update("audit_retention_days", 0).Error)
	removed, err := logquery.Prune(context.Background(), f.db, f.now)
	require.NoError(t, err)
	require.Zero(t, removed)

	require.NoError(t, f.db.Model(&model.Organization{}).Where("id = ?", f.org.ID).
		Update("audit_retention_days", 30).Error)
	removed, err = logquery.Prune(context.Background(), f.db, f.now)
	require.NoError(t, err)
	require.EqualValues(t, 2, removed)

	var conns []model.ConnectionLog
	require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).Find(&conns).Error)
	require.Len(t, conns, 1, fmt.Sprintf("only the fresh connection log must remain: %+v", conns))
	var files []model.FileLog
	require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).Find(&files).Error)
	require.Len(t, files, 1)
}
