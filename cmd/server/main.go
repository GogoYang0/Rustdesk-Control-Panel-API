// Command server is the control panel API entrypoint.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/api"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/device"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/logger"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/provision"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func main() {
	cfg, err := config.Load("configs/config.yaml")
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	lg, err := logger.New(cfg.Log)
	if err != nil {
		log.Fatalf("build logger: %v", err)
	}
	defer func() { _ = lg.Sync() }()

	if cfg.Auth.Secret == "" {
		lg.Fatal("auth.secret must be configured")
	}

	st, err := store.Open(cfg.Database)
	if err != nil {
		lg.Fatal("open database", zap.Error(err))
	}
	defer func() { _ = st.Close() }()

	if err := st.DB.AutoMigrate(
		&model.User{}, &model.RefreshToken{},
		&model.Organization{}, &model.Membership{}, &model.Invitation{},
		&model.AuditLog{},
		&model.Device{}, &model.DeviceHeartbeat{}, &model.ServerGroup{},
	); err != nil {
		lg.Fatal("migrate database", zap.Error(err))
	}

	issuer := auth.NewIssuer(cfg.Auth.Secret, cfg.Auth.AccessTTL, cfg.Auth.RefreshTTL)
	authSvc := auth.NewService(st.DB, issuer, zapLogger{lg})
	deviceSvc := device.NewService(st.DB, nil)
	orch := &provision.DockerOrchestrator{
		OrgLabel:  cfg.Provision.OrgLabel,
		RoleLabel: cfg.Provision.RoleLabel,
	}
	provSvc := provision.NewService(
		st.DB,
		provision.NewPortPool(st.DB, cfg.Provision.PortStart, cfg.Provision.PortEnd),
		orch,
		lg,
		provision.Config{
			Image:     cfg.Provision.Image,
			RelayHost: cfg.Provision.RelayHost,
			DataDir:   cfg.Provision.DataDir,
		},
	)
	provQueue := provision.NewQueue(provSvc, cfg.Provision.Workers, 0, lg)
	provQueue.Start(context.Background())
	// The organization row is the durable record of a provisioning intent, so a
	// sweep re-enqueues anything that never reached a worker (full queue, crash).
	go provQueue.RunReconciler(context.Background(), 2*time.Minute)

	srv := &http.Server{
		Addr: cfg.Server.Addr,
		Handler: api.NewRouter(api.Deps{
			DB:             st.DB,
			Auth:           authSvc,
			Devices:        deviceSvc,
			ProvisionQueue: provQueue,
			OrgsPerUser:    cfg.Provision.MaxOrgsPerUser,
			Issuer:         issuer,
			Auditor:        audit.NewGormAuditor(st.DB),
			Logger:         lg,
			AccessTTL:      cfg.Auth.AccessTTL,
			RefreshTTL:     cfg.Auth.RefreshTTL,
			InvitationTTL:  7 * 24 * time.Hour,
		}),
	}

	lg.Info("api listening", zap.String("addr", cfg.Server.Addr))
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		lg.Fatal("server stopped", zap.Error(err))
	}
}

// zapLogger adapts *zap.Logger to auth.Logger without widening the interface.
type zapLogger struct{ lg *zap.Logger }

func (l zapLogger) Info(msg string, keysAndValues ...any) {
	l.lg.Sugar().Infow(msg, keysAndValues...)
}
