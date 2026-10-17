package config_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
)

func TestLoad_ServerAddr(t *testing.T) {
	cfg, err := config.Load("../../configs/config.yaml")
	require.NoError(t, err)
	require.Equal(t, ":8080", cfg.Server.Addr)
	require.Equal(t, "info", cfg.Log.Level)
}
