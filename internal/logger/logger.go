// Package logger builds the process-wide structured logger.
package logger

import (
	"fmt"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
)

// New returns a zap logger configured from LogConfig.
func New(cfg config.LogConfig) (*zap.Logger, error) {
	level, err := zapcore.ParseLevel(cfg.Level)
	if err != nil {
		return nil, fmt.Errorf("parse log level %q: %w", cfg.Level, err)
	}

	zcfg := zap.NewProductionConfig()
	zcfg.Level = zap.NewAtomicLevelAt(level)

	if cfg.Format == "console" {
		zcfg.Encoding = "console"
	}

	logger, err := zcfg.Build()
	if err != nil {
		return nil, fmt.Errorf("build logger: %w", err)
	}

	return logger, nil
}
