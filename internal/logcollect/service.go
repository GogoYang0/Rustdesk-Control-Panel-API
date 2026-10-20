package logcollect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/device"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// parseErrorLogInterval rate-limits the "unparseable lines" warning: a broken
// rule set would otherwise flood the panel log at line rate (the counter is
// the signal; the log line only makes it discoverable).
const parseErrorLogInterval = time.Minute

// persistTimeout bounds one event write. The write itself is detached from the
// tailer's cancellation (see handleLine), so it needs its own upper bound.
const persistTimeout = 5 * time.Second

// Options tunes the collector.
type Options struct {
	// ContainerPrefix matches the provisioned container names
	// (<prefix>-<orgID>-hbbs / -hbbr).
	ContainerPrefix string
	InitialBackoff  time.Duration
	MaxBackoff      time.Duration
	// Streamer overrides the docker CLI streamer (tests).
	Streamer LineStreamer
	// PersistTimeout overrides the event-write bound (tests shorten it).
	PersistTimeout time.Duration
}

// Service runs one tailer pair per provisioned organization, parses the lines
// and stores tenant-scoped LogEvent rows.
type Service struct {
	db       *gorm.DB
	parser   *Parser
	streamer LineStreamer
	devices  *device.Service
	logger   *zap.Logger
	opts     Options
	now      func() time.Time

	mu      sync.Mutex
	wg      sync.WaitGroup
	ctx     context.Context
	watched map[uint]context.CancelFunc
	// closed is set by Wait: while it holds the lock, Watch can no longer
	// register work, which keeps Add strictly before Wait.
	closed bool

	// parseLogMu guards the rate-limited parse-error warning state.
	parseLogMu   sync.Mutex
	lastParseLog time.Time
	unloggedErrs uint64
}

// NewService builds the collector.
func NewService(db *gorm.DB, parser *Parser, streamer LineStreamer, devices *device.Service, opts Options, logger *zap.Logger) *Service {
	if opts.ContainerPrefix == "" {
		opts.ContainerPrefix = "panel-org"
	}
	if opts.Streamer != nil {
		streamer = opts.Streamer
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Service{
		db:       db,
		parser:   parser,
		streamer: streamer,
		devices:  devices,
		logger:   logger,
		opts:     opts,
		now:      time.Now,
		watched:  map[uint]context.CancelFunc{},
	}
}

// Start sweeps expired events and begins tailing every organization whose
// server group is deployed. The tailers stop when ctx is cancelled; Start
// itself returns immediately.
func (s *Service) Start(ctx context.Context) {
	s.mu.Lock()
	s.ctx = ctx
	s.mu.Unlock()

	s.pruneExpired()

	var rows []model.ServerGroup
	if err := store.WithoutTenantScope(s.db).
		Where("state = ?", model.ServerGroupDeployed).
		Find(&rows).Error; err != nil {
		s.logger.Error("load deployed server groups failed", zap.Error(err))
		return
	}
	for _, row := range rows {
		s.Watch(row.OrganizationID)
	}
	s.logger.Info("log collector started",
		zap.Int("organizations", len(rows)), zap.Int("rules", s.parser.Rules()))
}

// pruneExpired enforces the documented retention window at startup. M2 has no
// background scheduler yet, so the sweep runs once per process start; it is
// idempotent and bounded by the occurred_at index.
func (s *Service) pruneExpired() {
	// occurred_at is stored as UTC text and compared lexicographically, so the
	// cutoff must share that timeline: a local-zone value shifts the window by
	// the host's offset.
	cutoff := s.now().UTC().Add(-time.Duration(model.DefaultLogEventRetentionDays) * 24 * time.Hour)
	res := store.WithoutTenantScope(s.db).
		Where("occurred_at < ?", cutoff).
		Delete(&model.LogEvent{})
	if res.Error != nil {
		s.logger.Warn("prune expired log events failed", zap.Error(res.Error))
		return
	}
	if res.RowsAffected > 0 {
		s.logger.Info("pruned expired log events",
			zap.Int64("rows", res.RowsAffected),
			zap.Int("retention_days", model.DefaultLogEventRetentionDays))
	}
}

// Watch starts tailing one organization; repeated calls are no-ops, so the
// provisioning queue can call it after every successful deployment.
func (s *Service) Watch(orgID uint) {
	if orgID == 0 {
		return
	}
	roles := []string{model.LogSourceHbbs, model.LogSourceHbbr}

	s.mu.Lock()
	if s.closed {
		// Wait has started: registering would break the WaitGroup contract.
		s.mu.Unlock()
		return
	}
	if _, running := s.watched[orgID]; running {
		s.mu.Unlock()
		return
	}
	root := s.ctx
	if root == nil {
		root = context.Background()
	}
	// A provisioning worker detached with WithoutCancel can finish after
	// shutdown began and call Watch while main is draining.
	if root.Err() != nil {
		s.mu.Unlock()
		return
	}
	orgCtx, cancel := context.WithCancel(root)
	s.watched[orgID] = cancel
	// Add under the same lock that closes registration, so no Add can race
	// with Wait once it has started.
	s.wg.Add(len(roles))
	s.mu.Unlock()

	// A provisioning notification can also arrive after the organization was
	// deprovisioned (the row was deleted and Unwatch already ran): following
	// containers that no longer exist would leave two tailers retrying forever.
	// Only a successful lookup may cancel: a transient database error would
	// otherwise stop collection until the process restarts, because nothing
	// re-runs Watch for this organization.
	if deployed, err := s.deployed(orgID); err == nil && !deployed {
		s.Unwatch(orgID)
	}

	for _, role := range roles {
		tailer := &Tailer{
			Container:      s.containerName(orgID, role),
			Source:         role,
			OrgID:          orgID,
			Streamer:       s.streamer,
			Handler:        s.handleLine,
			Logger:         s.logger,
			InitialBackoff: s.opts.InitialBackoff,
			MaxBackoff:     s.opts.MaxBackoff,
			now:            s.now,
		}
		go func() {
			defer s.wg.Done()
			tailer.Run(orgCtx)
		}()
	}
}

// deployed reports whether the organization still has a deployed server group.
// The error is returned separately from the answer: a failed lookup says nothing
// about the deployment state.
func (s *Service) deployed(orgID uint) (bool, error) {
	var count int64
	err := store.WithoutTenantScope(s.db).Model(&model.ServerGroup{}).
		Where("organization_id = ? AND state = ?", orgID, model.ServerGroupDeployed).
		Count(&count).Error
	if err != nil {
		s.logger.Warn("check server group state failed",
			zap.Uint("org_id", orgID), zap.Error(err))
		return false, err
	}
	return count > 0, nil
}

// Unwatch stops the tailers of one organization (deprovisioning): without it a
// removed organization would keep two log-following processes alive forever.
func (s *Service) Unwatch(orgID uint) {
	s.mu.Lock()
	cancel, ok := s.watched[orgID]
	if ok {
		delete(s.watched, orgID)
	}
	s.mu.Unlock()
	if ok {
		cancel()
	}
}

// Wait blocks until every tailer goroutine has stopped (tests and shutdown).
// It closes registration first, so a late Watch cannot Add while Wait runs.
func (s *Service) Wait() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.wg.Wait()
}

// containerName renders the provisioned container name for one role.
func (s *Service) containerName(orgID uint, role string) string {
	return fmt.Sprintf("%s-%d-%s", s.opts.ContainerPrefix, orgID, role)
}

// handleLine parses one wire line and stores the event. Unparseable lines are
// counted by the parser and dropped (C7): the tailer never dies on bad input.
func (s *Service) handleLine(ctx context.Context, orgID uint, source, line string, at time.Time) error {
	before := s.parser.ParseErrors()
	event, ok := s.parser.Parse(line, at)
	if !ok {
		if s.parser.ParseErrors() > before {
			s.logParseError(orgID, source)
		}
		// A line that matches no rule is dropped by design (C7), not retried.
		return nil
	}

	// A line that was already read must reach the store even when the collector
	// is shutting down (Unwatch cancels the tailer context), otherwise the last
	// lines before a restart or a deprovisioning are lost silently. The detach
	// keeps a bound so a stuck database cannot block shutdown forever.
	persistDeadline := s.opts.PersistTimeout
	if persistDeadline <= 0 {
		persistDeadline = persistTimeout
	}
	persistCtx, cancelPersist := context.WithTimeout(context.WithoutCancel(ctx), persistDeadline)
	defer cancelPersist()

	var deviceID *uint
	if event.DeviceRustdeskID != "" {
		var dev model.Device
		err := store.ScopedByOrg(s.db.WithContext(persistCtx), orgID).
			Where("rustdesk_id = ?", event.DeviceRustdeskID).First(&dev).Error
		switch {
		case err == nil:
			deviceID = &dev.ID
			// Log activity is the auxiliary heartbeat source (C11): a real
			// connection proves the device is alive even if its client's
			// heartbeat is in flight.
			if s.devices != nil {
				if _, herr := s.devices.RecordLogActivity(persistCtx, orgID, event.DeviceRustdeskID, at); herr != nil {
					s.logger.Debug("log activity heartbeat failed",
						zap.Uint("org_id", orgID), zap.String("device", event.DeviceRustdeskID), zap.Error(herr))
				}
			}
		case errors.Is(err, gorm.ErrRecordNotFound):
			// The line references a device this organization does not track;
			// the event is still stored without the association.
		default:
			s.logger.Warn("resolve log device failed",
				zap.Uint("org_id", orgID), zap.Error(err))
		}
	}

	detail := "{}"
	if len(event.Detail) > 0 {
		if b, err := json.Marshal(event.Detail); err == nil {
			detail = string(b)
		}
	}
	// Stored as UTC: docker timestamps may carry an offset and untimestamped
	// lines fall back to the local zone, but SQLite orders these values as
	// text, so every row must share one offset.
	row := model.LogEvent{
		OrganizationID: orgID,
		DeviceID:       deviceID,
		Source:         source,
		Level:          event.Level,
		Kind:           event.Kind,
		DetailJSON:     detail,
		OccurredAt:     event.OccurredAt.UTC(),
	}
	// ScopedByOrg stores the tenant id in the context, so WithContext has to be
	// applied first: chaining it afterwards would drop the scope and the tenant
	// plugin would fail closed on every query.
	if err := store.ScopedByOrg(s.db.WithContext(persistCtx), orgID).Create(&row).Error; err != nil {
		s.logger.Error("store log event failed", zap.Uint("org_id", orgID), zap.Error(err))
		// Report the failure so the tailer keeps the resume point behind this
		// line and replays it after reconnecting.
		return err
	}
	return nil
}

// logParseError emits the unparseable-line signal at most once per interval.
// Without it a wrong rule set is invisible: the collector would simply store
// nothing and log nothing.
func (s *Service) logParseError(orgID uint, source string) {
	s.parseLogMu.Lock()
	s.unloggedErrs++
	now := s.now()
	if !s.lastParseLog.IsZero() && now.Sub(s.lastParseLog) < parseErrorLogInterval {
		s.parseLogMu.Unlock()
		return
	}
	dropped := s.unloggedErrs
	s.unloggedErrs = 0
	s.lastParseLog = now
	s.parseLogMu.Unlock()

	s.logger.Warn("unparseable log lines dropped; check the logcollect rules",
		zap.Uint("org_id", orgID), zap.String("source", source),
		zap.Uint64("dropped_since_last_report", dropped),
		zap.Uint64("parse_errors_total", s.parser.ParseErrors()))
}
