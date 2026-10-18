package auth_test

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

type captureLogger struct{ entries []string }

func (l *captureLogger) Info(msg string, keysAndValues ...any) {
	l.entries = append(l.entries, msg)
	for _, v := range keysAndValues {
		if s, ok := v.(string); ok {
			l.entries = append(l.entries, s)
		}
	}
}

// Review Focus #2: logs on the issue/rotation paths must never contain token material.
func TestLogNeverContainsToken(t *testing.T) {
	s, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: "file::memory:?cache=shared"})
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	require.NoError(t, s.DB.AutoMigrate(&model.User{}, &model.RefreshToken{}))

	logger := &captureLogger{}
	svc := auth.NewService(s.DB, auth.NewIssuer("test-secret", time.Minute, time.Hour), logger)

	access, refresh, err := svc.IssueTokens(11)
	require.NoError(t, err)

	_, newRefresh, err := svc.RotateRefresh(refresh)
	require.NoError(t, err)

	joined := strings.Join(logger.entries, " ")
	for _, secret := range []string{access, refresh, newRefresh} {
		require.NotContains(t, joined, secret, "logs must never contain token material")
	}
}
