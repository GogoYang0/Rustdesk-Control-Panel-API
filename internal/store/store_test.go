package store_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
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
}

func TestOpen_MySQL(t *testing.T) {
	dsn := testEnv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN not set")
	}
	s, err := store.Open(config.DatabaseConfig{Driver: "mysql", DSN: dsn})
	require.NoError(t, err)
	require.NoError(t, s.DB.AutoMigrate(&probeModel{}))
}

func testEnv(key string) string {
	return os.Getenv(key)
}
