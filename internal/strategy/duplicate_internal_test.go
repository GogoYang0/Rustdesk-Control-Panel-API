package strategy

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestIsDuplicateKeyError: the create/rename paths classify a lost race by the
// constraint error itself (the loser's PostgreSQL transaction is aborted, so an
// in-transaction re-check cannot run). The message forms differ per dialect.
func TestIsDuplicateKeyError(t *testing.T) {
	require.True(t, isDuplicateKeyError(
		errors.New(`ERROR: duplicate key value violates unique constraint "idx_strategy_org_namekey" (SQLSTATE 23505)`)))
	require.True(t, isDuplicateKeyError(
		errors.New("Error 1062: Duplicate entry 'Ops' for key 'idx_strategy_org_namekey'")))
	require.True(t, isDuplicateKeyError(
		errors.New("UNIQUE constraint failed: strategies.organization_id, strategies.name_key")))
	require.False(t, isDuplicateKeyError(errors.New("some other failure")))
	require.False(t, isDuplicateKeyError(nil))
}
