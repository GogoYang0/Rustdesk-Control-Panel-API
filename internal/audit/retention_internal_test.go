package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// verifyArchive is the gate between archiving and deleting rows; it must reject a
// truncated file or a digest mismatch.
func TestVerifyArchive_RejectsBadFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	require.NoError(t, os.WriteFile(path, []byte("{\"a\":1}\n{\"a\":2}\n"), 0o600))

	// Correct line count but wrong digest.
	require.Error(t, verifyArchive(path, strings.Repeat("0", 64), 2))
	// Correct digest but wrong line count.
	sum := sha256Hex(t, path)
	require.Error(t, verifyArchive(path, sum, 3))
	// Both correct.
	require.NoError(t, verifyArchive(path, sum, 2))
	// Missing file.
	require.Error(t, verifyArchive(filepath.Join(dir, "missing.jsonl"), sum, 2))
}

func sha256Hex(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// flakyRecorder fails the transactional audit on demand.
type flakyRecorder struct{ fail bool }

func (r *flakyRecorder) RecordTx(_ *gorm.DB, _ Entry) error {
	if r.fail {
		return errors.New("audit down")
	}
	return nil
}

// The archive is published before the deleting transaction. When that
// transaction fails, the batch stays and the next run must overwrite the same
// archive path instead of leaving one orphan file per failed attempt.
func TestRetention_RetryAfterTransactionFailureReusesArchivePath(t *testing.T) {
	dsn := fmt.Sprintf("file:retention_retry_%d?mode=memory&cache=shared", time.Now().UnixNano())
	st, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	require.NoError(t, st.DB.AutoMigrate(&model.Organization{}, &model.AuditLog{}))

	org := model.Organization{Name: "retry-org"}
	require.NoError(t, st.DB.Create(&org).Error)
	require.NoError(t, st.DB.Create(&model.AuditLog{
		OrganizationID: org.ID, Seq: 1, Action: "test.action",
		TargetType: "device", TargetID: "1",
		CreatedAt: time.Now().UTC().AddDate(0, 0, -40),
	}).Error)

	root := filepath.Join(t.TempDir(), "archives")
	rec := &flakyRecorder{fail: true}
	svc := NewRetentionService(st.DB, root, rec, nil)
	ctx := context.Background()
	require.NoError(t, svc.SetDays(ctx, org.ID, 30))

	_, _, err = svc.RunOnce(ctx)
	require.Error(t, err)
	pattern := filepath.Join(root, fmt.Sprintf("org-%d", org.ID), "audit-*.jsonl")
	files, ferr := filepath.Glob(pattern)
	require.NoError(t, ferr)
	require.Len(t, files, 1, "the failed transaction still leaves its archive")

	var remaining int64
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).
		Model(&model.AuditLog{}).Count(&remaining).Error)
	require.EqualValues(t, 1, remaining)

	rec.fail = false
	archived, purged, err := svc.RunOnce(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 1, archived)
	require.EqualValues(t, 1, purged)

	files, ferr = filepath.Glob(pattern)
	require.NoError(t, ferr)
	require.Len(t, files, 1, "the retry overwrites the same batch archive")
}

// A directory-sync failure must abort the batch before the deleting
// transaction. The retry must not trust directories created by the failed
// attempt: it re-syncs the whole existing chain, and when the sync still fails
// the rows stay in place again.
func TestRetention_SyncFailureKeepsRowsAndRetryResyncs(t *testing.T) {
	dsn := fmt.Sprintf("file:retention_sync_%d?mode=memory&cache=shared", time.Now().UnixNano())
	st, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	require.NoError(t, st.DB.AutoMigrate(&model.Organization{}, &model.AuditLog{}))

	org := model.Organization{Name: "sync-failure-org"}
	require.NoError(t, st.DB.Create(&org).Error)
	require.NoError(t, st.DB.Create(&model.AuditLog{
		OrganizationID: org.ID, Seq: 1, Action: "test.action",
		TargetType: "device", TargetID: "1",
		CreatedAt: time.Now().UTC().AddDate(0, 0, -40),
	}).Error)

	// Multi-level archive root that does not exist yet.
	root := filepath.Join(t.TempDir(), "a", "b", "c")
	svc := NewRetentionService(st.DB, root, NewGormAuditor(st.DB), nil)
	ctx := context.Background()
	require.NoError(t, svc.SetDays(ctx, org.ID, 30))

	// Fail on the parent of the leaf (the archive root) so the created chain
	// exists when the second attempt starts. Every flushed path is recorded to
	// assert the chain reaches the filesystem root.
	failParent := true
	var synced []string
	syncDirHook = func(dir string) error {
		synced = append(synced, dir)
		if failParent && dir == root {
			return errors.New("parent sync down")
		}
		return nil
	}
	t.Cleanup(func() { syncDirHook = nil })

	archived, purged, err := svc.RunOnce(ctx)
	require.Error(t, err)
	require.Zero(t, archived)
	require.Zero(t, purged)

	var remaining int64
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).
		Model(&model.AuditLog{}).Count(&remaining).Error)
	require.EqualValues(t, 1, remaining, "rows survive an unverifiable archive")

	// The directories now exist; the retry must sync them again instead of
	// assuming they are durable.
	archived, purged, err = svc.RunOnce(ctx)
	require.Error(t, err, "a still failing parent sync must keep the rows")
	require.Zero(t, archived)
	require.Zero(t, purged)
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).
		Model(&model.AuditLog{}).Count(&remaining).Error)
	require.EqualValues(t, 1, remaining)

	// Once the sync succeeds the retry re-syncs the chain, publishes the
	// archive and only then deletes the row.
	failParent = false
	archived, purged, err = svc.RunOnce(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 1, archived)
	require.EqualValues(t, 1, purged)
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).
		Model(&model.AuditLog{}).Count(&remaining).Error)
	require.EqualValues(t, 2, remaining, "only the archive/purge audit rows remain")

	volumeRoot := filepath.VolumeName(root) + string(os.PathSeparator)
	require.Contains(t, synced, volumeRoot, "the chain must reach the filesystem root")

	files, err := filepath.Glob(filepath.Join(root, fmt.Sprintf("org-%d", org.ID), "audit-*.jsonl"))
	require.NoError(t, err)
	require.Len(t, files, 1)
}

// A sync failure after the archive is published must keep the published files:
// they are valid on disk, the rows stay, and deleting them would risk removing
// an archive another concurrent attempt shares. The retry overwrites them.
func TestRetention_PostPublishSyncFailureKeepsArchive(t *testing.T) {
	dsn := fmt.Sprintf("file:retention_publish_%d?mode=memory&cache=shared", time.Now().UnixNano())
	st, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	require.NoError(t, st.DB.AutoMigrate(&model.Organization{}, &model.AuditLog{}))

	org := model.Organization{Name: "post-publish-org"}
	require.NoError(t, st.DB.Create(&org).Error)
	require.NoError(t, st.DB.Create(&model.AuditLog{
		OrganizationID: org.ID, Seq: 1, Action: "test.action",
		TargetType: "device", TargetID: "1",
		CreatedAt: time.Now().UTC().AddDate(0, 0, -40),
	}).Error)

	root := filepath.Join(t.TempDir(), "archives")
	leaf := filepath.Join(root, fmt.Sprintf("org-%d", org.ID))
	svc := NewRetentionService(st.DB, root, NewGormAuditor(st.DB), nil)
	ctx := context.Background()
	require.NoError(t, svc.SetDays(ctx, org.ID, 30))

	// The first leaf sync happens while creating the directory chain; the second
	// one follows the publication of both files.
	leafSyncs := 0
	syncDirHook = func(dir string) error {
		if dir == leaf {
			leafSyncs++
			if leafSyncs == 2 {
				return errors.New("post-publish sync down")
			}
		}
		return nil
	}
	t.Cleanup(func() { syncDirHook = nil })

	archived, purged, err := svc.RunOnce(ctx)
	require.Error(t, err)
	require.Zero(t, archived)
	require.Zero(t, purged)

	files, gerr := filepath.Glob(filepath.Join(leaf, "audit-*.jsonl"))
	require.NoError(t, gerr)
	require.Len(t, files, 1, "the published archive survives a failed directory sync")
	_, statErr := os.Stat(files[0] + ".sha256")
	require.NoError(t, statErr, "the checksum file is published too")
	tmps, gerr := filepath.Glob(filepath.Join(leaf, "audit-*.tmp"))
	require.NoError(t, gerr)
	require.Empty(t, tmps, "this attempt's temp files are cleaned up")

	var remaining int64
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).
		Model(&model.AuditLog{}).Count(&remaining).Error)
	require.EqualValues(t, 1, remaining, "rows survive an unflushed archive")

	syncDirHook = nil
	archived, purged, err = svc.RunOnce(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 1, archived)
	require.EqualValues(t, 1, purged)
	files, gerr = filepath.Glob(filepath.Join(leaf, "audit-*.jsonl"))
	require.NoError(t, gerr)
	require.Len(t, files, 1, "the retry overwrites the same published path")
}

// A failed checksum publication must not delete the already published data
// file: a concurrent attempt may have published that exact path.
func TestRetention_ChecksumPublishFailureKeepsDataFile(t *testing.T) {
	dsn := fmt.Sprintf("file:retention_checksum_%d?mode=memory&cache=shared", time.Now().UnixNano())
	st, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	require.NoError(t, st.DB.AutoMigrate(&model.Organization{}, &model.AuditLog{}))

	org := model.Organization{Name: "checksum-org"}
	require.NoError(t, st.DB.Create(&org).Error)
	row := model.AuditLog{
		OrganizationID: org.ID, Seq: 1, Action: "test.action",
		TargetType: "device", TargetID: "1",
		CreatedAt: time.Now().UTC().AddDate(0, 0, -40),
	}
	require.NoError(t, st.DB.Create(&row).Error)

	root := filepath.Join(t.TempDir(), "archives")
	leaf := filepath.Join(root, fmt.Sprintf("org-%d", org.ID))
	require.NoError(t, os.MkdirAll(leaf, 0o750))
	// Renaming onto an existing directory fails on every platform, so the
	// checksum publication errors after the data file is already in place.
	blocked := filepath.Join(leaf, fmt.Sprintf("audit-%d-%d.jsonl.sha256", row.ID, row.ID))
	require.NoError(t, os.Mkdir(blocked, 0o750))

	svc := NewRetentionService(st.DB, root, NewGormAuditor(st.DB), nil)
	ctx := context.Background()
	require.NoError(t, svc.SetDays(ctx, org.ID, 30))

	archived, purged, err := svc.RunOnce(ctx)
	require.Error(t, err)
	require.Zero(t, archived)
	require.Zero(t, purged)

	dataFile := filepath.Join(leaf, fmt.Sprintf("audit-%d-%d.jsonl", row.ID, row.ID))
	_, statErr := os.Stat(dataFile)
	require.NoError(t, statErr, "the published data file is never deleted by a failed attempt")
	tmps, gerr := filepath.Glob(filepath.Join(leaf, "audit-*.tmp"))
	require.NoError(t, gerr)
	require.Empty(t, tmps, "this attempt's temp files are cleaned up")

	var remaining int64
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).
		Model(&model.AuditLog{}).Count(&remaining).Error)
	require.EqualValues(t, 1, remaining)
}
