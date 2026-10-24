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
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/api"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/device"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/logcollect"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/logger"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/mail"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/provision"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/session"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/worker"
)

// main loads configuration, prepares persistence and services, and starts the API server.
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
		&model.CompatSession{},
		&model.LogEvent{},
		&model.Session{}, &model.SessionEvent{},
		&model.Ticket{}, &model.Policy{},
		&model.Approval{}, &model.Alert{},
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
		if err := st.DB.Clauses(clause.OnConflict{DoNothing: true}).Create(&model.MigrationMark{
			Name:      backfillEmailVerifiedTrue,
			AppliedAt: time.Now().UTC(),
		}).Error; err != nil {
			lg.Fatal("record backfill marker", zap.Error(err))
		}
	case err != nil:
		lg.Fatal("read migration marker", zap.Error(err))
	}

	issuer := auth.NewIssuer(cfg.Auth.Secret, cfg.Auth.AccessTTL, cfg.Auth.RefreshTTL)
	authSvc := auth.NewService(st.DB, issuer, zapLogger{lg})

	// The shared audit recorder: the device service needs it before the API
	// layer is built (binding resets must commit with their audit entry), so it
	// is created here rather than next to the session service.
	auditor := audit.NewGormAuditor(st.DB)

	deviceSvc := device.NewService(st.DB, auditor, nil)
	orch := &provision.DockerOrchestrator{
		OrgLabel:  cfg.Provision.OrgLabel,
		RoleLabel: cfg.Provision.RoleLabel,
	}
	provSvc := provision.NewService(
		st.DB,
		provision.NewPortPool(st.DB, cfg.Provision.PortStart, cfg.Provision.PortEnd),
		orch,
		auditor,
		lg,
		provision.Config{
			Image:     cfg.Provision.Image,
			RelayHost: cfg.Provision.RelayHost,
			DataDir:   cfg.Provision.DataDir,
			PortStart: cfg.Provision.PortStart,
			PortEnd:   cfg.Provision.PortEnd,
		},
	)
	provQueue := provision.NewQueue(provSvc, cfg.Provision.Workers, 0, lg)

	// rootCtx stops the long-running background workers on SIGINT/SIGTERM so
	// their docker child processes are not orphaned.
	rootCtx, stopRoot := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopRoot()
	// Handling the first signal disables the default termination for the whole
	// shutdown window, so a second Ctrl-C would be swallowed while a request or
	// a tailer is still draining. Restoring the default handling as soon as the
	// context is cancelled keeps the operator's force-quit escape hatch.
	context.AfterFunc(rootCtx, stopRoot)

	// Mail delivery: devMode prints to stdout; otherwise real SMTP. The
	// validation below exits the process on misconfiguration, so it runs before
	// any background worker: lg.Fatal skips every defer and would otherwise
	// leave docker children and in-flight provisions behind.
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

	// One session service shared by the API handlers, the log collector's
	// session hook and the background tasks: all three mutate the same rows,
	// so they must see one clock and one audit recorder.
	sessionSvc := session.NewService(st.DB, auditor, time.Now)

	// Log collection: one tailer pair per provisioned organization. The queue
	// hook starts the tailers of a fresh deployment immediately instead of
	// waiting for the next process start.
	var collector *logcollect.Service
	if cfg.Logcollect.Enabled {
		parser, perr := logcollect.NewParser(logcollectRules(cfg.Logcollect.Rules))
		if perr != nil {
			lg.Fatal("invalid logcollect rules", zap.Error(perr))
		}
		collector = logcollect.NewService(
			st.DB, parser, logcollect.DockerCLIStreamer{}, deviceSvc,
			logcollect.Options{ContainerPrefix: cfg.Logcollect.ContainerPrefix, Sessions: logcollect.SessionRecorderFunc(sessionSvc.ReportLogEvent)}, lg,
		)
		collector.Start(rootCtx)
		provQueue.OnProvisioned(collector.Watch)
		// A deprovisioned organization no longer has containers to follow.
		provSvc.OnDeprovisioned(collector.Unwatch)
		lg.Info("log collector enabled", zap.Int("rules", parser.Rules()))
	}

	provQueue.Start(rootCtx)

	// Background workers: the retention sweep must run regardless of whether
	// log collection itself is enabled (#41), and every pass is audited so
	// infrastructure housekeeping stays observable (#46).

	// Tenant transfers are the one write path that can move a row between
	// organizations. The store refuses them unless a recorder is registered, so
	// wiring it here is what makes the channel usable at all; leaving it out
	// keeps the channel closed.
	store.RegisterTransferRecorder(func(tx *gorm.DB, aud store.TransferAudit) error {
		return auditor.RecordTx(tx, audit.Entry{
			OrganizationID: aud.OrganizationID,
			ActorUserID:    aud.ActorUserID,
			Action:         "tenant.transfer",
			TargetType:     "organization",
			Detail:         map[string]any{"reason": aud.Reason},
		})
	})
	sched := worker.New(lg, auditor)

	// Pending approvals expire on their own deadline; the sweep only marks
	// the rows so the inbox stops offering dead requests.
	if err := sched.Register(worker.Task{
		Name:       "approval-expiry",
		Interval:   time.Minute,
		RunOnStart: true,
		Run: func(ctx context.Context) (int64, error) {
			return sessionSvc.ExpirePendingApprovals(ctx, time.Now())
		},
	}); err != nil {
		lg.Fatal("register approval expiry sweep", zap.Error(err))
	}

	// Session maintenance: the idle sweep closes sessions whose trail went
	// quiet (otherwise a lost-log session would hold its concurrency slot
	// forever), and the duration sweep enforces max_session_minutes after the
	// fact — the panel is not in the signalling path, so the real connection
	// is never cut, only recorded and alerted. The idle window is deployment
	// configurable (session.idleTimeout, default 10m) per the contract.
	idleWindow := cfg.Session.IdleTimeout
	if idleWindow <= 0 {
		// A misconfigured window must not silently disable the sweep.
		lg.Warn("session.idleTimeout is not positive; falling back to the default",
			zap.Duration("configured", cfg.Session.IdleTimeout),
			zap.Duration("using", session.DefaultIdleWindow))
		idleWindow = session.DefaultIdleWindow
	}
	if err := sched.Register(worker.Task{
		Name:       "session-idle",
		Interval:   time.Minute,
		RunOnStart: true,
		Run: func(ctx context.Context) (int64, error) {
			return sessionSvc.CloseIdleSessions(ctx, time.Now(), idleWindow)
		},
	}); err != nil {
		lg.Fatal("register idle session sweep", zap.Error(err))
	}
	if err := sched.Register(worker.Task{
		Name:       "session-duration",
		Interval:   time.Minute,
		RunOnStart: true,
		Run: func(ctx context.Context) (int64, error) {
			return sessionSvc.ClosePolicyExceededSessions(ctx, time.Now())
		},
	}); err != nil {
		lg.Fatal("register duration session sweep", zap.Error(err))
	}

	if cfg.Logcollect.RetentionSweepInterval > 0 {
		if err := sched.Register(worker.Task{
			Name:     "logcollect-retention",
			Interval: cfg.Logcollect.RetentionSweepInterval,
			// The startup pass doubles as the first sweep, so a disabled
			// collector still trims overdue history right after boot (#41).
			RunOnStart: true,
			Run: func(ctx context.Context) (int64, error) {
				return logcollect.PruneExpired(st.DB.WithContext(ctx), time.Now())
			},
		}); err != nil {
			lg.Fatal("register retention sweep", zap.Error(err))
		}
	} else {
		lg.Warn("periodic retention sweep disabled (logcollect.retentionSweepInterval = 0)")
	}
	sched.Start(rootCtx)

	// Drain the tailers on shutdown: exec.CommandContext kills the
	// `docker logs -f` children only when their context is cancelled, and
	// waiting here keeps them from outliving the panel.
	var drainCollector func()
	if collector != nil {
		// Stop the scheduler and drain the tailers concurrently: a stuck
		// `docker logs` drain must not keep in-flight sweeps writing to a
		// database that is about to be closed.
		drainCollector = func() {
			var wg sync.WaitGroup
			wg.Add(2)
			go func() { defer wg.Done(); sched.Stop() }()
			go func() { defer wg.Done(); collector.Wait() }()
			wg.Wait()
		}
	} else {
		drainCollector = sched.Stop
	}
	// The organization row is the durable record of a provisioning intent, so a
	// sweep re-enqueues anything that never reached a worker (full queue, crash).
	go provQueue.RunReconciler(rootCtx, 2*time.Minute)

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
			Auditor:        auditor,
			Logger:         lg,
			Mailer:         mailer,
			Tickets:        sessionSvc,
			AccessTTL:      cfg.Auth.AccessTTL,
			RefreshTTL:     cfg.Auth.RefreshTTL,
			InvitationTTL:  7 * 24 * time.Hour,
			WebBaseURL:     cfg.Web.BaseURL,
			CompatTTL:      cfg.Compat.AccessTTL,
		}),
	}

	ln, err := net.Listen("tcp", cfg.Server.Addr)
	if err != nil {
		lg.Fatal("listen", zap.String("addr", cfg.Server.Addr), zap.Error(err))
	}
	lg.Info("api listening", zap.String("addr", ln.Addr().String()))
	if err := serveUntilShutdown(rootCtx, srv, ln, drainCollector, lg, gracefulShutdownTimeout); err != nil {
		lg.Fatal("server stopped", zap.Error(err))
	}
}

// gracefulShutdownTimeout bounds how long in-flight requests may keep the
// process alive once a termination signal arrives.
const gracefulShutdownTimeout = 15 * time.Second

// serveUntilShutdown serves srv on ln and returns either when the listener
// fails or when ctx is cancelled. Draining on cancellation keeps two promises
// that signal.NotifyContext alone breaks: once a signal is notified the runtime
// no longer terminates the process by default, so a main that only blocks in
// ListenAndServe ignores SIGINT/SIGTERM entirely (the default configuration has
// log collection disabled and therefore no other goroutine watching ctx), and
// returning instead of calling os.Exit lets every deferred cleanup run.
func serveUntilShutdown(
	ctx context.Context,
	srv *http.Server,
	ln net.Listener,
	drain func(),
	lg *zap.Logger,
	timeout time.Duration,
) error {
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	select {
	case err := <-serveErr:
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	}

	// Stop accepting new connections and let in-flight requests finish
	// (provisioning is asynchronous, so this is short).
	shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		lg.Warn("graceful shutdown did not finish", zap.Error(err))
	}
	if drain != nil {
		// A docker CLI child that cannot be killed leaves Wait blocked, so the
		// drain gets the same bound: the process is exiting anyway and the
		// children are terminated with it.
		drained := make(chan struct{})
		go func() {
			drain()
			close(drained)
		}()
		select {
		case <-drained:
		case <-time.After(timeout):
			lg.Warn("background workers did not stop in time", zap.Duration("timeout", timeout))
		}
	}
	return nil
}

// zapLogger adapts *zap.Logger to auth.Logger without widening the interface.
type zapLogger struct{ lg *zap.Logger }

func (l zapLogger) Info(msg string, keysAndValues ...any) {
	l.lg.Sugar().Infow(msg, keysAndValues...)
}

// logcollectRules converts the config shape into parser rules.
func logcollectRules(rules []config.LogcollectRule) []logcollect.Rule {
	out := make([]logcollect.Rule, 0, len(rules))
	for _, r := range rules {
		out = append(out, logcollect.Rule{
			Name:    r.Name,
			Pattern: r.Pattern,
			Level:   r.Level,
			Kind:    r.Kind,
		})
	}
	return out
}

// isPublicHTTPSOrigin reports whether raw is a well-formed https origin
// (scheme + host, no path/query) that points neither at loopback nor at a
// private address: this panel is a multi-tenant SaaS, and email links embed
// plaintext tokens, so an unreachable intranet origin is a misconfiguration.
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
	if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsPrivate()) {
		return false
	}
	return true
}
