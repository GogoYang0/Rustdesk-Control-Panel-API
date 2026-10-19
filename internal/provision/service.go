package provision

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// ErrAlreadyProvisioned is returned when a deployed group already exists.
var ErrAlreadyProvisioned = errors.New("organization already provisioned")

// Service provisions one hbbs/hbbr pair per organization.
type Service struct {
	db     *gorm.DB
	pool   *PortPool
	orch   Orchestrator
	logger *zap.Logger
}

// NewService builds the provisioning service.
func NewService(db *gorm.DB, pool *PortPool, orch Orchestrator, logger *zap.Logger) *Service {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Service{db: db, pool: pool, orch: orch, logger: logger}
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
// result. Any failure releases the ports and removes the container.
func (s *Service) ProvisionForOrg(ctx context.Context, orgID uint) (*model.ServerGroup, error) {
	if err := store.RequireOrgID(orgID); err != nil {
		return nil, err
	}

	var existing model.ServerGroup
	err := store.ScopedByOrg(s.db, orgID).First(&existing).Error
	if err == nil && existing.State == model.ServerGroupDeployed {
		return nil, fmt.Errorf("%w", ErrAlreadyProvisioned)
	}
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("load server group: %w", err)
	}

	row, err := s.pool.Allocate(orgID)
	if err != nil {
		return nil, err
	}

	keys, err := GenerateKeyPair()
	if err != nil {
		s.release(row)
		return nil, err
	}

	spec := InstanceSpec{
		Name:       fmt.Sprintf("panel-org-%d", orgID),
		OrgID:      orgID,
		HbbsPort:   row.HbbsPort,
		HbbrPort:   row.HbbrPort,
		PrivatePEM: keys.PrivatePEM,
	}
	if err := s.orch.Deploy(ctx, spec); err != nil {
		// Roll back: the container may exist half-configured, and the ports must
		// be released so a retry can use them.
		if rmErr := s.orch.Remove(ctx, spec.Name); rmErr != nil {
			s.logger.Warn("provision rollback: remove failed",
				zap.String("instance", spec.Name), zap.Error(rmErr))
		}
		s.release(row)
		return nil, fmt.Errorf("deploy hbbs/hbbr: %w", err)
	}

	snap, err := json.Marshal(snapshot{
		HbbsPort:    row.HbbsPort,
		HbbrPort:    row.HbbrPort,
		PublicKey:   keys.PublicKey,
		Fingerprint: keys.Fingerprint,
	})
	if err != nil {
		s.rollback(ctx, spec, row)
		return nil, fmt.Errorf("snapshot config: %w", err)
	}

	err = store.ScopedByOrg(s.db, orgID).Model(&model.ServerGroup{}).
		Where("id = ?", row.ID).
		Updates(map[string]any{
			"pub_key":         keys.PublicKey,
			"fingerprint":     keys.Fingerprint,
			"config_snapshot": string(snap),
			"state":           model.ServerGroupDeployed,
		}).Error
	if err != nil {
		s.rollback(ctx, spec, row)
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
	if err := s.orch.Remove(ctx, name); err != nil {
		// Keep the row: the container still exists, so the ports stay reserved.
		return fmt.Errorf("remove deployment: %w", err)
	}
	return store.ScopedByOrg(s.db, orgID).Delete(&model.ServerGroup{}, row.ID).Error
}

// rollback removes the deployment and the pending row.
func (s *Service) rollback(ctx context.Context, spec InstanceSpec, row *model.ServerGroup) {
	if err := s.orch.Remove(ctx, spec.Name); err != nil {
		s.logger.Warn("provision rollback: remove failed",
			zap.String("instance", spec.Name), zap.Error(err))
	}
	s.release(row)
}

// release deletes the pending row so the ports become available again.
func (s *Service) release(row *model.ServerGroup) {
	if err := store.ScopedByOrg(s.db, row.OrganizationID).
		Delete(&model.ServerGroup{}, row.ID).Error; err != nil {
		s.logger.Error("release ports failed",
			zap.Uint("org_id", row.OrganizationID), zap.Error(err))
	}
}
