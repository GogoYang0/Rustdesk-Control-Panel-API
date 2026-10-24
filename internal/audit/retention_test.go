package audit_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

type retentionRecorder struct {
	entries []audit.Entry
}

func (r *retentionRecorder) RecordTx(_ *gorm.DB, e audit.Entry) error {
	r.entries = append(r.entries, e)
	return nil
}

func newRetentionFixture(t *testing.T) (*audit.RetentionService, *store.Store, *retentionRecorder, model.Organization, string) {
	t.Helper()
	dsn := fmt.Sprintf("file:retention_%d?mode=memory&cache=shared", time.Now().UnixNano())
	st, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	require.NoError(t, st.DB.AutoMigrate(&model.Organization{}, &model.AuditLog{}))

	org := model.Organization{Name: "retention-org"}
	require.NoError(t, st.DB.Create(&org).Error)
	dir := t.TempDir()
	rec := &retentionRecorder{}
	return audit.NewRetentionService(st.DB, dir, rec, nil), st, rec, org, dir
}

func seedRetentionRow(t *testing.T, st *store.Store, orgID uint, seq uint64, at time.Time) {
	t.Helper()
	require.NoError(t, st.DB.Create(&model.AuditLog{
		OrganizationID: orgID,
		Seq:            seq,
		ActorUserID:    3,
		Action:         "test.action",
		TargetType:     "device",
		TargetID:       "1",
		CreatedAt:      at,
	}).Error)
}

func TestAuditRetention_ArchivesThenPurges(t *testing.T) {
	svc, st, rec, org, dir := newRetentionFixture(t)
	ctx := context.Background()

	old := time.Now().UTC().AddDate(0, 0, -40)
	seedRetentionRow(t, st, org.ID, 1, old)
	seedRetentionRow(t, st, org.ID, 2, time.Now().UTC())

	require.NoError(t, svc.SetDays(ctx, org.ID, 30))
	archived, purged, err := svc.RunOnce(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 1, archived)
	require.EqualValues(t, 1, purged)

	orgDir := filepath.Join(dir, fmt.Sprintf("org-%d", org.ID))
	files, err := filepath.Glob(filepath.Join(orgDir, "audit-*.jsonl"))
	require.NoError(t, err)
	require.Len(t, files, 1)
	data, err := os.ReadFile(files[0])
	require.NoError(t, err)
	require.Equal(t, 1, strings.Count(strings.TrimSpace(string(data)), "\n")+1, "one JSON row per line")

	sum := sha256.Sum256(data)
	sumFile, err := os.ReadFile(files[0] + ".sha256")
	require.NoError(t, err)
	require.Contains(t, string(sumFile), hex.EncodeToString(sum[:]))

	var remaining []model.AuditLog
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).Find(&remaining).Error)
	require.Len(t, remaining, 1)
	require.EqualValues(t, 2, remaining[0].Seq, "only the expired row is purged")

	require.Len(t, rec.entries, 2)
	require.Equal(t, "audit.retention.archive", rec.entries[0].Action)
	require.Equal(t, "audit.retention.purge", rec.entries[1].Action)
	require.Zero(t, rec.entries[0].ActorUserID, "retention is a system action")
	require.Equal(t, files[0], rec.entries[0].Detail["path"])
}

func TestAuditRetention_LatestUsesTheAuditor(t *testing.T) {
	_, st, _, org, dir := newRetentionFixture(t)
	ctx := context.Background()
	seedRetentionRow(t, st, org.ID, 1, time.Now().UTC().AddDate(0, 0, -40))

	svc := audit.NewRetentionService(st.DB, dir, audit.NewGormAuditor(st.DB), nil)
	require.NoError(t, svc.SetDays(ctx, org.ID, 30))
	archived, purged, err := svc.RunOnce(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 1, archived)
	require.EqualValues(t, 1, purged)

	latest, err := svc.Latest(ctx, org.ID)
	require.NoError(t, err)
	require.True(t, latest.Found)
	require.Equal(t, 1, latest.Rows)
	require.NotEmpty(t, latest.Path)
}

func TestAuditRetention_ArchiveFailureKeepsRows(t *testing.T) {
	svc, st, rec, org, dir := newRetentionFixture(t)
	ctx := context.Background()
	seedRetentionRow(t, st, org.ID, 1, time.Now().UTC().AddDate(0, 0, -40))

	// Replace the archive dir with a regular file so creating org-<id> fails.
	blocker := filepath.Join(dir, "blocked")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))
	svc = audit.NewRetentionService(st.DB, blocker, rec, nil)
	require.NoError(t, svc.SetDays(ctx, org.ID, 30))

	archived, purged, err := svc.RunOnce(ctx)
	require.Error(t, err)
	require.Zero(t, archived)
	require.Zero(t, purged)
	require.Empty(t, rec.entries, "a failed archive must not be audited as success")

	var remaining int64
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).Model(&model.AuditLog{}).Count(&remaining).Error)
	require.EqualValues(t, 1, remaining, "rows survive an unverifiable archive")
}

func TestAuditRetention_NoRecorderFailsClosed(t *testing.T) {
	_, st, _, org, dir := newRetentionFixture(t)
	ctx := context.Background()
	seedRetentionRow(t, st, org.ID, 1, time.Now().UTC().AddDate(0, 0, -40))
	svc := audit.NewRetentionService(st.DB, dir, nil, nil)
	require.NoError(t, svc.SetDays(ctx, org.ID, 30))

	_, _, err := svc.RunOnce(ctx)
	require.Error(t, err)

	var remaining int64
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).Model(&model.AuditLog{}).Count(&remaining).Error)
	require.EqualValues(t, 1, remaining)
}

func TestAuditRetention_SetDaysValidation(t *testing.T) {
	svc, _, _, org, _ := newRetentionFixture(t)
	ctx := context.Background()

	require.ErrorIs(t, svc.SetDays(ctx, org.ID, -1), audit.ErrInvalidRetention)
	require.ErrorIs(t, svc.SetDays(ctx, org.ID, audit.MaxRetentionDays+1), audit.ErrInvalidRetention)
	require.NoError(t, svc.SetDays(ctx, org.ID, 0))
	days, err := svc.Get(ctx, org.ID)
	require.NoError(t, err)
	require.Zero(t, days)

	require.NoError(t, svc.SetDays(ctx, org.ID, 7))
	days, err = svc.Get(ctx, org.ID)
	require.NoError(t, err)
	require.Equal(t, 7, days)

	require.ErrorIs(t, svc.SetDays(ctx, 999999, 7), gorm.ErrRecordNotFound)
}
