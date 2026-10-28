package scopetest

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// openClientBuildDialectDB uses the CI-provided PostgreSQL/MySQL DSN when
// present, so the client-build tables are migrated and queried on all three
// supported dialects instead of SQLite only.
func openClientBuildDialectDB(t *testing.T) (*gorm.DB, func()) {
	t.Helper()
	var (
		s   *store.Store
		err error
	)
	switch {
	case os.Getenv("TEST_POSTGRES_DSN") != "":
		s, err = store.Open(config.DatabaseConfig{Driver: "postgres", DSN: os.Getenv("TEST_POSTGRES_DSN")})
	case os.Getenv("TEST_MYSQL_DSN") != "":
		s, err = store.Open(config.DatabaseConfig{Driver: "mysql", DSN: os.Getenv("TEST_MYSQL_DSN")})
	default:
		s, err = store.Open(config.DatabaseConfig{
			Driver: "sqlite",
			DSN:    fmt.Sprintf("file:cb_scopetest_%d?mode=memory&cache=shared", time.Now().UnixNano()),
		})
	}
	require.NoError(t, err)
	require.NoError(t, s.DB.AutoMigrate(&model.Organization{}, &model.Membership{}))
	return s.DB, func() { _ = s.Close() }
}
