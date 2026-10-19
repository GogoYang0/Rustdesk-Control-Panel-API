package provision

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// cleanupTimeout bounds rollback work, which must not inherit the deploy
// deadline: the deploy context may already be cancelled.
const cleanupTimeout = 30 * time.Second

// Config carries deployment settings.
type Config struct {
	Image     string
	RelayHost string
	DataDir   string
}

// Service provisions one hbbs/hbbr pair per organization.
type Service struct {
	db     *gorm.DB
	pool   *PortPool
	orch   Orchestrator
	logger *zap.Logger
	cfg    Config
}

// NewService builds the provisioning service.
func NewService(db *gorm.DB, pool *PortPool, orch Orchestrator, logger *zap.Logger, cfg Config) *Service {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Service{db: db, pool: pool, orch: orch, logger: logger, cfg: cfg}
}

// snapshot is the subset written to ServerGroup.ConfigSnapshot. It never
// contains the private key.
type snapshot struct {
	HbbsPort    uint16 `json:"hbbs_port"`
	HbbrPort    uint16 `json:"hbbr_port"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
}

// ProvisionForOrg allocates ports, generates keys, deploys and persists the
// result. Any failure releases the ports and removes the containers.
func (s *Service) ProvisionForOrg(ctx context.Context, orgID uint) (*model.ServerGroup, error) {
	if err := store.RequireOrgID(orgID); err != nil {
		return nil, err
	}

	row, err := s.pool.Allocate(orgID)
	if err != nil {
		return nil, err
	}

	keys, err := GenerateKeyPair()
	if err != nil {
		s.releaseWithCleanup(row)
		return nil, err
	}

	spec := InstanceSpec{
		Name:       fmt.Sprintf("panel-org-%d", orgID),
		OrgID:      orgID,
		HbbsPort:   row.HbbsPort,
		HbbrPort:   row.HbbrPort,
		PrivateKey: keys.PrivateKey,
		PublicKey:  keys.PublicKey,
		Image:      s.cfg.Image,
		RelayHost:  s.cfg.RelayHost,
		DataDir:    filepath.Join(s.cfg.DataDir, fmt.Sprintf("org-%d", orgID)),
	}

	if err := s.orch.Deploy(ctx, spec); err != nil {
		s.failAndCleanup(ctx, row, spec, err)
		return nil, fmt.Errorf("deploy hbbs/hbbr: %w", err)
	}

	snap, err := json.Marshal(snapshot{
		HbbsPort:    row.HbbsPort,
		HbbrPort:    row.HbbrPort,
		PublicKey:   keys.PublicKey,
		Fingerprint: keys.Fingerprint,
	})
	if err != nil {
		s.failAndCleanup(ctx, row, spec, err)
		return nil, fmt.Errorf("snapshot config: %w", err)
	}

	err = store.ScopedByOrg(s.db, orgID).Model(&model.ServerGroup{}).
		Where("id = ?", row.ID).
		Updates(map[string]any{
			"pub_key":         keys.PublicKey,
			"fingerprint":     keys.Fingerprint,
			"config_snapshot": string(snap),
			"state":           model.ServerGroupDeployed,
			"last_error":      "",
		}).Error
	if err != nil {
		s.failAndCleanup(ctx, row, spec, err)
		return nil, fmt.Errorf("persist server group: %w", err)
	}

	s.logger.Info("provisioned hbbs/hbbr",
		zap.Uint("org_id", orgID),
		zap.Uint16("hbbs_port", row.HbbsPort),
		zap.String("fingerprint", keys.Fingerprint))

	var stored model.ServerGroup
	if err := store.ScopedByOrg(s.db, orgID).First(&stored, row.ID).Error; err != nil {
		return nil, fmt.Errorf("reload server group: %w", err)
	}
	return &stored, nil
}

// Deprovision removes the deployment and frees the ports.
func (s *Service) Deprovision(ctx context.Context, orgID uint) error {
	if err := store.RequireOrgID(orgID); err != nil {
		return err
	}

	var row model.ServerGroup
	if err := store.ScopedByOrg(s.db, orgID).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		return fmt.Errorf("load server group: %w", err)
	}

	name := fmt.Sprintf("panel-org-%d", orgID)
	if err := s.orch.Remove(cleanupContext(ctx), name); err != nil {
		// Keep the row: the containers may still exist, so the ports stay
		// reserved instead of being handed to another organization.
		s.markFailed(&row, fmt.Errorf("remove deployment: %w", err))
		return fmt.Errorf("remove deployment: %w", err)
	}
	return store.ScopedByOrg(s.db, orgID).Delete(&model.ServerGroup{}, row.ID).Error
}

// failAndCleanup rolls back a failed deployment. When removal fails the row is
// kept in the failed state so the ports stay reserved for a later retry.
func (s *Service) failAndCleanup(ctx context.Context, row *model.ServerGroup, spec InstanceSpec, cause error) {
	cleanupCtx := cleanupContext(ctx)
	if err := s.orch.Remove(cleanupCtx, spec.Name); err != nil {
		s.logger.Warn("provision rollback: remove failed, keeping ports reserved",
			zap.String("instance", spec.Name), zap.Error(err))
		s.markFailed(row, cause)
		return
	}
	s.release(row)
}

// releaseWithCleanup releases the ports after a local failure.
func (s *Service) releaseWithCleanup(row *model.ServerGroup) {
	s.release(row)
}

// markFailed records the failure while keeping the row and its ports.
func (s *Service) markFailed(row *model.ServerGroup, cause error) {
	msg := ""
	if cause != nil {
		msg = cause.Error()
	}
	if err := store.ScopedByOrg(s.db, row.OrganizationID).
		Model(&model.ServerGroup{}).
		Where("id = ?", row.ID).
		Updates(map[string]any{
			"state":      model.ServerGroupFailed,
			"last_error": msg,
		}).Error; err != nil {
		s.logger.Error("mark server group failed",
			zap.Uint("org_id", row.OrganizationID), zap.Error(err))
	}
}

// release deletes the pending row so the ports become available again.
func (s *Service) release(row *model.ServerGroup) {
	if err := store.ScopedByOrg(s.db, row.OrganizationID).
		Delete(&model.ServerGroup{}, row.ID).Error; err != nil {
		s.logger.Error("release ports failed",
			zap.Uint("org_id", row.OrganizationID), zap.Error(err))
	}
}

// cleanupContext detaches cleanup from a cancelled deploy context.
func cleanupContext(ctx context.Context) context.Context {
	base := context.WithoutCancel(ctx)
	out, cancel := context.WithTimeout(base, cleanupTimeout)
	// The timeout is short and the context is only used for the cleanup call.
	_ = cancel
	return out
}
