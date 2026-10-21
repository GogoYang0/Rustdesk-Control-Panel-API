package store_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// probeModel is a throwaway model used to verify the store can migrate and CRUD.
type probeModel struct {
	ID   uint   `gorm:"primaryKey"`
	Name string `gorm:"size:64"`
}

func (probeModel) TableName() string { return "probe_models" }

func TestOpen_SqliteMemory(t *testing.T) {
	s, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: "file::memory:?cache=shared"})
	require.NoError(t, err)
	require.NotNil(t, s)

	require.NoError(t, s.DB.AutoMigrate(&probeModel{}))
	require.NoError(t, s.DB.Create(&probeModel{Name: "hello"}).Error)

	var got probeModel
	require.NoError(t, s.DB.First(&got).Error)
	require.Equal(t, "hello", got.Name)
}

func TestOpen_UnsupportedDriver(t *testing.T) {
	_, err := store.Open(config.DatabaseConfig{Driver: "oracle", DSN: "x"})
	require.Error(t, err)
}

func TestOpen_SqliteCreatesDir(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "nested", "sub", "test.db")

	s, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	require.NoError(t, s.DB.AutoMigrate(&probeModel{}))

	_, err = os.Stat(filepath.Join(dir, "nested", "sub", "test.db"))
	require.NoError(t, err)
}

func TestOpen_Postgres(t *testing.T) {
	dsn := testEnv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN not set")
	}
	s, err := store.Open(config.DatabaseConfig{Driver: "postgres", DSN: dsn})
	require.NoError(t, err)
	require.NoError(t, s.DB.AutoMigrate(&probeModel{}))
	requireGovernanceSchema(t, s.DB)
}

func TestOpen_MySQL(t *testing.T) {
	dsn := testEnv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN not set")
	}
	s, err := store.Open(config.DatabaseConfig{Driver: "mysql", DSN: dsn})
	require.NoError(t, err)
	require.NoError(t, s.DB.AutoMigrate(&probeModel{}))
	requireGovernanceSchema(t, s.DB)
}

// The same assertion runs on SQLite so the expected names are checked locally
// too, not only in CI where the Postgres/MySQL tests get their DSNs.
func TestGovernanceSchema_SQLite(t *testing.T) {
	s, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: "file:gov_schema?mode=memory&cache=shared"})
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	requireGovernanceSchema(t, s.DB)
}

// governanceIndexes are the composite/unique indexes the six tables rely on.
// A typo in a gorm tag produces no error on SQLite (it just builds whatever the
// tag says) and only surfaces as a slow query or a missing constraint, so the
// names are asserted explicitly.
var governanceIndexes = []struct{ table, index string }{
	{"sessions", "idx_session_org_status"},
	{"sessions", "idx_session_org_started"},
	{"sessions", "idx_session_device"},
	{"session_events", "idx_session_event_session"},
	{"tickets", "idx_ticket_org_device"},
	{"policies", "idx_policy_org_name"},
	{"approvals", "idx_approval_org_status"},
	{"alerts", "idx_alert_org_created"},
}

// requireGovernanceSchema builds the session-governance schema on whatever
// dialect the test runs against and asserts the tables and indexes exist.
//
// Until this existed, no non-SQLite dialect had ever created these tables: the
// CI matrix only migrated probeModel, so a tag MySQL rejects would have surfaced
// at a customer's first start instead of in CI.
func requireGovernanceSchema(t *testing.T, db *gorm.DB) {
	t.Helper()
	require.NoError(t, db.AutoMigrate(
		&model.Session{}, &model.SessionEvent{}, &model.Ticket{},
		&model.Policy{}, &model.Approval{}, &model.Alert{},
	))
	for _, table := range []string{"sessions", "session_events", "tickets", "policies", "approvals", "alerts"} {
		require.True(t, db.Migrator().HasTable(table), "%s must be created", table)
	}
	for _, idx := range governanceIndexes {
		require.True(t, db.Migrator().HasIndex(idx.table, idx.index),
			"%s must exist on %s", idx.index, idx.table)
	}
}

func testEnv(key string) string {
	return os.Getenv(key)
}
