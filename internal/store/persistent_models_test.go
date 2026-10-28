package store_test

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm/schema"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func TestPersistentModels_CoverScopedModels(t *testing.T) {
	st, err := store.Open(config.DatabaseConfig{
		Driver: "sqlite", DSN: "file:persistent_models_guard?mode=memory&cache=shared",
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	scoped := tableNames(t, store.ScopedModels())
	persistent := tableNames(t, model.PersistentModels())
	for table := range scoped {
		require.Truef(t, persistent[table],
			"%s is tenant-scoped but missing from model.PersistentModels()", table)
	}
	require.True(t, persistent["strategies"])
	require.True(t, persistent["device_disconnects"])
}

func tableNames(t *testing.T, models []any) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, m := range models {
		if tn, ok := m.(interface{ TableName() string }); ok {
			out[tn.TableName()] = true
			continue
		}
		s, err := schema.Parse(m, &sync.Map{}, schema.NamingStrategy{})
		require.NoError(t, err)
		out[s.Table] = true
	}
	return out
}
