package model_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

func int64p(v int64) *int64 { return &v }

// MinInt64 folds optional policy bounds: nil means "no limit", so it must never
// win against a real value, and a real value must never win against a stricter
// one.
func TestMinInt64(t *testing.T) {
	require.Nil(t, model.MinInt64(nil, nil), "two unbounded limits stay unbounded")

	require.Equal(t, int64(5), *model.MinInt64(int64p(5), nil), "a bound beats unbounded")
	require.Equal(t, int64(5), *model.MinInt64(nil, int64p(5)), "unbounded loses to a bound")

	require.Equal(t, int64(3), *model.MinInt64(int64p(5), int64p(3)), "the stricter bound wins")
	require.Equal(t, int64(3), *model.MinInt64(int64p(3), int64p(5)), "order must not matter")

	require.Equal(t, int64(7), *model.MinInt64(int64p(7), int64p(7)), "equal bounds are stable")
}
