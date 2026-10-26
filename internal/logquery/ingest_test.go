package logquery_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/logquery"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

var ingestSeq atomic.Int64

func openStore(t *testing.T) *store.Store {
	t.Helper()
	switch {
	case os.Getenv("TEST_POSTGRES_DSN") != "":
		s, err := store.Open(config.DatabaseConfig{Driver: "postgres", DSN: os.Getenv("TEST_POSTGRES_DSN")})
		require.NoError(t, err)
		return s
	case os.Getenv("TEST_MYSQL_DSN") != "":
		s, err := store.Open(config.DatabaseConfig{Driver: "mysql", DSN: os.Getenv("TEST_MYSQL_DSN")})
		require.NoError(t, err)
		return s
	}
	s, err := store.Open(config.DatabaseConfig{
		Driver: "sqlite",
		DSN:    fmt.Sprintf("file:logquery_%d?mode=memory&cache=shared", ingestSeq.Add(1)),
	})
	require.NoError(t, err)
	return s
}

type fixture struct {
	ing    *logquery.Ingest
	db     *gorm.DB
	org    model.Organization
	device model.Device
	now    time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	s := openStore(t)
	t.Cleanup(func() { _ = s.Close() })
	require.NoError(t, s.DB.AutoMigrate(
		&model.Organization{}, &model.Device{}, &model.ConnectionLog{},
		&model.FileLog{}, &model.AuditNonce{}, &model.AuditLog{},
	))
	f := &fixture{db: s.DB, now: time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)}
	f.org = model.Organization{Name: "acme"}
	require.NoError(t, f.db.Create(&f.org).Error)
	f.device = model.Device{
		OrganizationID: f.org.ID,
		RustdeskID:     "123456789",
		Name:           "pc",
		BoundUUID:      "uuid-abc",
	}
	require.NoError(t, f.db.Create(&f.device).Error)
	f.ing = logquery.New(f.db, audit.NewGormAuditor(f.db), func() time.Time { return f.now })
	return f
}

func (f *fixture) connPayload(action, nonce string) logquery.ConnPayload {
	return logquery.ConnPayload{
		ID:        f.device.RustdeskID,
		UUID:      f.device.BoundUUID,
		Action:    action,
		IP:        "203.0.113.9",
		ConnID:    77,
		SessionID: 4242,
		Nonce:     nonce,
	}
}

func (f *fixture) connLogs(t *testing.T) []model.ConnectionLog {
	t.Helper()
	var rows []model.ConnectionLog
	require.NoError(t, store.WithoutTenantScope(f.db).Order("id").Find(&rows).Error)
	return rows
}

func TestConn_NewThenClose(t *testing.T) {
	f := newFixture(t)
	dedup, err := f.ing.Conn(context.Background(), f.connPayload("new", "n1"))
	require.NoError(t, err)
	require.False(t, dedup)

	rows := f.connLogs(t)
	require.Len(t, rows, 1)
	require.Equal(t, model.ConnectionLogStatusOpen, rows[0].Status)
	require.Nil(t, rows[0].EndedAt)
	require.Equal(t, "203.0.113.9", rows[0].IP)
	require.Equal(t, f.device.ID, rows[0].DeviceID)

	f.now = f.now.Add(5 * time.Minute)
	_, err = f.ing.Conn(context.Background(), f.connPayload("close", "n2"))
	require.NoError(t, err)

	rows = f.connLogs(t)
	require.Len(t, rows, 1)
	require.Equal(t, model.ConnectionLogStatusClosed, rows[0].Status)
	require.NotNil(t, rows[0].EndedAt)
}

func TestConn_CloseOnlyTouchesItsOwnConnID(t *testing.T) {
	f := newFixture(t)
	_, err := f.ing.Conn(context.Background(), f.connPayload("new", "a"))
	require.NoError(t, err)
	second := f.connPayload("new", "b")
	second.ConnID = 88
	_, err = f.ing.Conn(context.Background(), second)
	require.NoError(t, err)

	closeFirst := f.connPayload("close", "c")
	_, err = f.ing.Conn(context.Background(), closeFirst)
	require.NoError(t, err)

	rows := f.connLogs(t)
	require.Len(t, rows, 2)
	require.Equal(t, model.ConnectionLogStatusClosed, rows[0].Status)
	require.Equal(t, model.ConnectionLogStatusOpen, rows[1].Status)
}

func TestConn_DuplicateNonceIsIdempotent(t *testing.T) {
	f := newFixture(t)
	_, err := f.ing.Conn(context.Background(), f.connPayload("new", "same"))
	require.NoError(t, err)
	dedup, err := f.ing.Conn(context.Background(), f.connPayload("new", "same"))
	require.NoError(t, err)
	require.True(t, dedup)
	require.Len(t, f.connLogs(t), 1)
}

func TestConn_NoteAppendsToLatestOpenRow(t *testing.T) {
	f := newFixture(t)
	_, err := f.ing.Conn(context.Background(), f.connPayload("new", "n"))
	require.NoError(t, err)

	_, err = f.ing.Conn(context.Background(), logquery.ConnPayload{
		ID: f.device.RustdeskID, SessionID: 4242, Note: "first",
	})
	require.NoError(t, err)
	_, err = f.ing.Conn(context.Background(), logquery.ConnPayload{
		ID: f.device.RustdeskID, SessionID: 4242, Note: "second",
	})
	require.NoError(t, err)

	rows := f.connLogs(t)
	require.Len(t, rows, 1)
	require.Contains(t, rows[0].Note, "first")
	require.Contains(t, rows[0].Note, "second")
}

func TestIngest_RejectsUUIDMismatch(t *testing.T) {
	f := newFixture(t)
	bad := f.connPayload("new", "x")
	bad.UUID = "another-uuid"
	_, err := f.ing.Conn(context.Background(), bad)
	require.ErrorIs(t, err, logquery.ErrIdentityMismatch)

	empty := f.connPayload("new", "y")
	empty.UUID = ""
	_, err = f.ing.Conn(context.Background(), empty)
	require.ErrorIs(t, err, logquery.ErrIdentityMismatch)
}

func TestIngest_RejectsUnknownDevice(t *testing.T) {
	f := newFixture(t)
	unknown := f.connPayload("new", "z")
	unknown.ID = "999999999"
	_, err := f.ing.Conn(context.Background(), unknown)
	require.ErrorIs(t, err, logquery.ErrUnknownDevice)
}

func TestIngest_RejectsMalformed(t *testing.T) {
	f := newFixture(t)
	_, err := f.ing.Conn(context.Background(), logquery.ConnPayload{ID: f.device.RustdeskID, UUID: f.device.BoundUUID, Action: "bogus", Nonce: "m"})
	require.ErrorIs(t, err, logquery.ErrMalformed)
}

func TestFile_StoresDirectionAndInfo(t *testing.T) {
	f := newFixture(t)
	info, err := json.Marshal(map[string]any{
		"ip":    "198.51.100.7",
		"name":  "controller",
		"num":   2,
		"files": [][2]any{{"a.txt", 10}, {"b.txt", 20}},
	})
	require.NoError(t, err)
	dedup, ferr := f.ing.File(context.Background(), logquery.FilePayload{
		ID: f.device.RustdeskID, UUID: f.device.BoundUUID,
		PeerID: "555", ConnID: 77, Type: 0, Path: "/tmp", IsFile: false,
		Info: string(info), Nonce: "f1",
	})
	require.NoError(t, ferr)
	require.False(t, dedup)

	var rows []model.FileLog
	require.NoError(t, store.WithoutTenantScope(f.db).Find(&rows).Error)
	require.Len(t, rows, 1)
	require.Equal(t, "send", rows[0].Direction)
	require.Equal(t, 2, rows[0].FileCount)
	require.Contains(t, rows[0].FilesJSON, "a.txt")
	require.Equal(t, "198.51.100.7", rows[0].IP)
	require.Equal(t, "controller", rows[0].Name)

	f.now = f.now.Add(time.Second)
	_, ferr = f.ing.File(context.Background(), logquery.FilePayload{
		ID: f.device.RustdeskID, UUID: f.device.BoundUUID, Type: 1, Nonce: "f2",
	})
	require.NoError(t, ferr)
	rows = nil
	require.NoError(t, store.WithoutTenantScope(f.db).Order("id").Find(&rows).Error)
	require.Equal(t, "receive", rows[1].Direction)
}

func TestAlarm_WritesAuditRow(t *testing.T) {
	f := newFixture(t)
	dedup, err := f.ing.Alarm(context.Background(), logquery.AlarmPayload{
		ID: f.device.RustdeskID, UUID: f.device.BoundUUID,
		Typ: 9, Info: `{"message":"scope violation"}`, ConnID: 77, Nonce: "al1",
	})
	require.NoError(t, err)
	require.False(t, dedup)

	var rows []model.AuditLog
	require.NoError(t, store.WithoutTenantScope(f.db).Find(&rows).Error)
	require.Len(t, rows, 1)
	require.Equal(t, f.org.ID, rows[0].OrganizationID)
	require.Equal(t, "client.alarm.session_scope_violation", rows[0].Action)
	require.Contains(t, rows[0].Detail, "scope violation")
	require.Equal(t, f.device.RustdeskID, rows[0].TargetID)
}

func TestSweepNonces_DropsOnlyExpired(t *testing.T) {
	f := newFixture(t)
	_, err := f.ing.Conn(context.Background(), f.connPayload("new", "old"))
	require.NoError(t, err)

	f.now = f.now.Add(30 * time.Minute)
	_, err = f.ing.Conn(context.Background(), logquery.ConnPayload{
		ID: f.device.RustdeskID, UUID: f.device.BoundUUID, Action: "new", Nonce: "fresh",
		ConnID: 99, SessionID: 100,
	})
	require.NoError(t, err)

	removed, err := f.ing.SweepNonces(context.Background(), f.now, 10*time.Minute)
	require.NoError(t, err)
	require.EqualValues(t, 1, removed)

	var rows []model.AuditNonce
	require.NoError(t, store.WithoutTenantScope(f.db).Find(&rows).Error)
	require.Len(t, rows, 1)
	require.Equal(t, "fresh", rows[0].Nonce)
}

// TestIngest_NoteScopedToOwningOrganization pins the fix for the one
// unauthenticated write path that used to run without a tenant condition: the
// note must land on the device's own organization, never on another tenant's
// row that happens to carry the same rustdesk id and session id.
func TestIngest_NoteScopedToOwningOrganization(t *testing.T) {
	f := newFixture(t)
	otherOrg := model.Organization{Name: "globex"}
	require.NoError(t, f.db.Create(&otherOrg).Error)
	otherDev := model.Device{OrganizationID: otherOrg.ID, RustdeskID: "800001", Name: "other"}
	require.NoError(t, store.ScopedByOrg(f.db, otherOrg.ID).Create(&otherDev).Error)
	// A decoy row in the other organization with the same id/session pair.
	require.NoError(t, store.ScopedByOrg(f.db, otherOrg.ID).Create(&model.ConnectionLog{
		OrganizationID: otherOrg.ID, DeviceID: otherDev.ID, RustdeskID: otherDev.RustdeskID,
		ConnID: 1, SessionID: 4242, Status: model.ConnectionLogStatusOpen, StartedAt: f.now,
	}).Error)
	// The real target lives in f.org.
	require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).Create(&model.ConnectionLog{
		OrganizationID: f.org.ID, DeviceID: f.device.ID, RustdeskID: f.device.RustdeskID,
		ConnID: 1, SessionID: 4242, Status: model.ConnectionLogStatusOpen, StartedAt: f.now,
	}).Error)

	_, err := f.ing.Conn(context.Background(), logquery.ConnPayload{
		ID: f.device.RustdeskID, SessionID: 4242, Note: "scoped",
	})
	require.NoError(t, err)

	var other model.ConnectionLog
	require.NoError(t, store.ScopedByOrg(f.db, otherOrg.ID).First(&other).Error)
	require.Empty(t, other.Note, "the other tenant's row must stay untouched")
	var own model.ConnectionLog
	require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).First(&own).Error)
	require.Equal(t, "scoped", own.Note)
}

// TestIngest_RejectsAmbiguousIdentity: the same (id, uuid) in two organizations
// is a cross-tenant write waiting to happen, so it fails closed.
func TestIngest_RejectsAmbiguousIdentity(t *testing.T) {
	f := newFixture(t)
	otherOrg := model.Organization{Name: "globex"}
	require.NoError(t, f.db.Create(&otherOrg).Error)
	require.NoError(t, store.ScopedByOrg(f.db, otherOrg.ID).Create(&model.Device{
		OrganizationID: otherOrg.ID, RustdeskID: f.device.RustdeskID, Name: "clone",
		BoundUUID: f.device.BoundUUID,
	}).Error)

	_, err := f.ing.Conn(context.Background(), f.connPayload("new", "amb-1"))
	require.ErrorIs(t, err, logquery.ErrAmbiguousDevice)
}

func TestIngest_RejectsOversizedField(t *testing.T) {
	f := newFixture(t)
	p := f.connPayload("new", "big-1")
	p.IP = fmt.Sprintf("%0*d", 65, 1)
	_, err := f.ing.Conn(context.Background(), p)
	require.ErrorIs(t, err, logquery.ErrMalformed)
}
