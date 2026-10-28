package clientbuild

import (
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
)

type Service struct {
	db       *gorm.DB
	recorder audit.TxRecorder
	auditor  audit.Auditor
	cfg      Config
	storage  *Storage
	github   GitHubClient
	logger   *zap.Logger
	now      func() time.Time
}

func NewService(
	db *gorm.DB,
	recorder audit.TxRecorder,
	auditor audit.Auditor,
	cfg Config,
	github GitHubClient,
	logger *zap.Logger,
	now func() time.Time,
) (*Service, error) {
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	cfg.PublicBaseURL = strings.TrimRight(cfg.PublicBaseURL, "/")
	storage, err := NewStorage(cfg.AssetDir)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	if now == nil {
		now = time.Now
	}
	return &Service{
		db:       db,
		recorder: recorder,
		auditor:  auditor,
		cfg:      cfg,
		storage:  storage,
		github:   github,
		logger:   logger,
		now:      now,
	}, nil
}

func (s *Service) Config() Config { return s.cfg }

func normalizePage(page, pageSize int) (int, int) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 50
	}
	if pageSize > 200 {
		pageSize = 200
	}
	return page, pageSize
}
