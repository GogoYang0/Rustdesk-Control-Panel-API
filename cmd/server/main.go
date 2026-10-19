// Command server is the control panel API entrypoint.
package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/api"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/device"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/logger"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/mail"
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

	// backfillEmailVerifiedTrue is the persistent marker for the one-time
	// data migration that trusts pre-verification accounts as verified.
	const backfillEmailVerifiedTrue = "backfill_email_verified_true"

	if err := st.DB.AutoMigrate(
		&model.User{}, &model.RefreshToken{},
		&model.Organization{}, &model.Membership{}, &model.Invitation{},
		&model.AuditLog{},
		&model.Device{}, &model.DeviceHeartbeat{}, &model.ServerGroup{},
		&model.AddressBook{}, &model.AddressBookPeer{},
		&model.AddressBookTag{}, &model.SyncCursor{},
		&model.VerificationToken{},
		&model.MigrationMark{},
	); err != nil {
		lg.Fatal("migrate database", zap.Error(err))
	}

	// One-time backfill, guarded by a persistent marker instead of the
	// column's existence: if the data migration itself fails, the next boot
	// must retry it, not skip it. The column carries NOT NULL DEFAULT false,
	// so upgraded rows arrive as false (or NULL on a legacy nullable
	// column); every account created before email verification existed (M1)
	// went through the invitation password-proving chain and is trusted as
	// verified. Accounts created afterwards start unverified.
	var mark model.MigrationMark
	err = st.DB.Where("name = ?", backfillEmailVerifiedTrue).First(&mark).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		res := st.DB.Model(&model.User{}).
			Where("email_verified IS NULL OR email_verified = ?", false).
			Update("email_verified", true)
		if res.Error != nil {
			// Die without writing the marker: the next start retries.
			lg.Fatal("backfill email_verified", zap.Error(res.Error))
		}
		lg.Info("backfilled email_verified for existing users", zap.Int64("rows", res.RowsAffected))
		if err := st.DB.Create(&model.MigrationMark{Name: backfillEmailVerifiedTrue}).Error; err != nil {
			lg.Fatal("record backfill marker", zap.Error(err))
		}
	case err != nil:
		lg.Fatal("read migration marker", zap.Error(err))
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

	// Mail delivery: devMode prints to stdout; otherwise real SMTP. The
	// SMTP password comes only from PANEL_SMTP_PASSWORD.
	var mailer mail.Mailer
	if cfg.Mail.DevMode {
		mailer = mail.NewDev(os.Stdout)
		lg.Info("mail delivery in devMode: messages are written to stdout")
	} else {
		if cfg.Mail.SMTP.Host == "" || cfg.Mail.SMTP.From == "" {
			lg.Fatal("mail.devMode is false but mail.smtp.host/from is empty")
		}
		if cfg.Mail.SMTP.Username != "" && os.Getenv("PANEL_SMTP_PASSWORD") == "" {
			// dialSMTP would still attempt AUTH with the empty password and
			// every delivery would fail at runtime; refuse to start instead.
			lg.Fatal("PANEL_SMTP_PASSWORD is required when mail.smtp.username is set")
		}
		if !isPublicHTTPSOrigin(cfg.Web.BaseURL) {
			// Every mail embeds the plaintext token in a link built from this
			// origin. A localhost or plain-http default would silently hand
			// verification and invitation links to an unusable (or
			// interceptable) destination.
			lg.Fatal("web.baseURL must be a public https origin when mail.devMode is false")
		}
		mailer = mail.NewSMTP(mail.SMTPConfig{
			Host:     cfg.Mail.SMTP.Host,
			Port:     cfg.Mail.SMTP.Port,
			Username: cfg.Mail.SMTP.Username,
			Password: os.Getenv("PANEL_SMTP_PASSWORD"),
			From:     cfg.Mail.SMTP.From,
		})
	}

	srv := &http.Server{
		Addr: cfg.Server.Addr,
		// Timeouts are mandatory: without a read header deadline an unauthenticated
		// client can hold connections and goroutines open with a slow request
		// (Slowloris). Provisioning is asynchronous, so writes stay short.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		Handler: api.NewRouter(api.Deps{
			DB:             st.DB,
			Auth:           authSvc,
			Devices:        deviceSvc,
			ProvisionQueue: provQueue,
			OrgsPerUser:    cfg.Provision.MaxOrgsPerUser,
			Issuer:         issuer,
			Auditor:        audit.NewGormAuditor(st.DB),
			Logger:         lg,
			Mailer:         mailer,
			AccessTTL:      cfg.Auth.AccessTTL,
			RefreshTTL:     cfg.Auth.RefreshTTL,
			InvitationTTL:  7 * 24 * time.Hour,
			WebBaseURL:     cfg.Web.BaseURL,
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

// isPublicHTTPSOrigin reports whether raw is a well-formed https origin
// (scheme + host, no path/query) that does not point at loopback.
func isPublicHTTPSOrigin(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" ||
		u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return false
	}
	host := u.Hostname()
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return false
	}
	return true
}
