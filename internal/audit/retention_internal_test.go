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
