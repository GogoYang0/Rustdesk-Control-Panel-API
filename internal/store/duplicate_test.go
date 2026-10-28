package store_test

import (
	"errors"
	"fmt"
	"testing"

	"gorm.io/gorm"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// TestIsDuplicateKeyError covers both shapes: the gorm-translated form
// ("duplicated key not allowed", produced by the MySQL/SQLite drivers with
// TranslateError enabled and matched by none of the vendor message strings)
// and the raw vendor messages.
func TestIsDuplicateKeyError(t *testing.T) {
	require.True(t, store.IsDuplicateKeyError(fmt.Errorf("wrapped: %w", gorm.ErrDuplicatedKey)))
	require.True(t, store.IsDuplicateKeyError(errors.New("ERROR: duplicate key value violates unique constraint \"x\"")))
	require.True(t, store.IsDuplicateKeyError(errors.New("Error 1062: Duplicate entry 'a-b' for key 'idx'")))
	require.True(t, store.IsDuplicateKeyError(errors.New("UNIQUE constraint failed: t.id")))
	require.False(t, store.IsDuplicateKeyError(errors.New("connection refused")))
	require.False(t, store.IsDuplicateKeyError(nil))
}
