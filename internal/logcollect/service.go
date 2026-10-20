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

// Options tunes the collector.
type Options struct {
	// ContainerPrefix matches the provisioned container names
	// (<prefix>-<orgID>-hbbs / -hbbr).
	ContainerPrefix string
	InitialBackoff  time.Duration
	MaxBackoff      time.Duration
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
	watched map[uint]bool
}

// NewService builds the collector.
func NewService(db *gorm.DB, parser *Parser, streamer LineStreamer, devices *device.Service, opts Options, logger *zap.Logger) *Service {
	if opts.ContainerPrefix == "" {
		opts.ContainerPrefix = "panel-org"
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
		watched:  map[uint]bool{},
	}
}

// Start begins tailing every organization whose server group is deployed. The
// tailers stop when ctx is cancelled; Start itself returns immediately.
func (s *Service) Start(ctx context.Context) {
	s.mu.Lock()
	s.ctx = ctx
	s.mu.Unlock()

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
	s.logger.Info("log collector started", zap.Int("organizations", len(rows)))
}

// Watch starts tailing one organization; repeated calls are no-ops, so the
// provisioning queue can call it after every successful deployment.
func (s *Service) Watch(orgID uint) {
	if orgID == 0 {
		return
	}
	s.mu.Lock()
	if s.watched[orgID] {
		s.mu.Unlock()
		return
	}
	s.watched[orgID] = true
	root := s.ctx
	if root == nil {
		root = context.Background()
	}
	s.mu.Unlock()

	for _, role := range []string{model.LogSourceHbbs, model.LogSourceHbbr} {
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
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			tailer.Run(root)
		}()
	}
}

// Wait blocks until every tailer goroutine has stopped (tests and shutdown).
func (s *Service) Wait() { s.wg.Wait() }

// containerName renders the provisioned container name for one role.
func (s *Service) containerName(orgID uint, role string) string {
	return fmt.Sprintf("%s-%d-%s", s.opts.ContainerPrefix, orgID, role)
}

// handleLine parses one wire line and stores the event. Unparseable lines are
// counted by the parser and dropped (C7): the tailer never dies on bad input.
func (s *Service) handleLine(orgID uint, source, line string, at time.Time) {
	event, ok := s.parser.Parse(line, at)
	if !ok {
		s.logger.Debug("unparseable log line dropped",
			zap.Uint("org_id", orgID), zap.String("source", source))
		return
	}

	var deviceID *uint
	if event.DeviceRustdeskID != "" {
		var dev model.Device
		err := store.ScopedByOrg(s.db, orgID).
			Where("rustdesk_id = ?", event.DeviceRustdeskID).First(&dev).Error
		switch {
		case err == nil:
			deviceID = &dev.ID
			// Log activity is the auxiliary heartbeat source (C11): a real
			// connection proves the device is alive even if its client's
			// heartbeat is in flight.
			if s.devices != nil {
				if _, herr := s.devices.RecordLogActivity(context.Background(), orgID, event.DeviceRustdeskID, at); herr != nil {
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
	row := model.LogEvent{
		OrganizationID: orgID,
		DeviceID:       deviceID,
		Source:         source,
		Level:          event.Level,
		Kind:           event.Kind,
		DetailJSON:     detail,
		OccurredAt:     event.OccurredAt,
	}
	if err := store.ScopedByOrg(s.db, orgID).Create(&row).Error; err != nil {
		s.logger.Error("store log event failed", zap.Uint("org_id", orgID), zap.Error(err))
	}
}
