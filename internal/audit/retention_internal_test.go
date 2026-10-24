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
// transaction: the expired rows stay in place for the next cycle.
func TestRetention_SyncFailureKeepsRows(t *testing.T) {
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

	svc := NewRetentionService(st.DB, t.TempDir(), NewGormAuditor(st.DB), nil)
	ctx := context.Background()
	require.NoError(t, svc.SetDays(ctx, org.ID, 30))

	syncDirHook = func(string) error { return errors.New("sync down") }
	t.Cleanup(func() { syncDirHook = nil })

	archived, purged, err := svc.RunOnce(ctx)
	require.Error(t, err)
	require.Zero(t, archived)
	require.Zero(t, purged)

	var remaining int64
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).
		Model(&model.AuditLog{}).Count(&remaining).Error)
	require.EqualValues(t, 1, remaining, "rows survive an unverifiable archive")
}
