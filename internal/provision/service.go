package provision

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// cleanupTimeout bounds rollback work, which must not inherit the deploy
// deadline: the deploy context may already be cancelled.
const cleanupTimeout = 30 * time.Second

// orgLockStripes bounds the number of per-organization transition locks. A
// striped array avoids an unbounded map of mutexes; collisions only make two
// unrelated organizations wait for one container removal.
const orgLockStripes = 64

// staleProvisioningGrace bounds how long a provisioning row may still belong to
// a live deploy job. The queue job times out after five minutes, so an older
// row cannot have containers that are still being created by this process.
const staleProvisioningGrace = 10 * time.Minute

// deployTimeout bounds one container start. The queue already bounds the whole
// job, but explicit ProvisionForOrg calls may arrive with a deadline-free
// context; without this bound a stuck deploy would outlive the grace period the
// disable path relies on.
var deployTimeout = jobTimeout

// Config carries deployment settings.
type Config struct {
	Image     string
	RelayHost string
	DataDir   string
	// PortStart and PortEnd describe the host range a deployment may use. They
	// mirror provision.portStart/portEnd and drive the startup port probe.
	PortStart uint16
	PortEnd   uint16
}

// Service provisions one hbbs/hbbr pair per organization.
type Service struct {
	db       *gorm.DB
	pool     *PortPool
	orch     Orchestrator
	recorder audit.TxRecorder
	checker  PortChecker
	logger   *zap.Logger
	cfg      Config

	mu              sync.Mutex
	onDeprovisioned func(orgID uint)

	// orgLocks serialise the state transitions (disable, enable, allocate,
	// persist) of one organization. The provisioning queue and reconciler are
	// in-process, so this is the supported deployment shape; the database flag
	// check and RowsAffected guard stay in place as a backstop for rows written
	// outside the lock.
	orgLocks [orgLockStripes]sync.Mutex
}

// lockOrg serialises provisioning transitions for one organization and returns
// the unlock function.
func (s *Service) lockOrg(orgID uint) func() {
	m := &s.orgLocks[orgID%orgLockStripes]
	m.Lock()
	return m.Unlock
}

// OnDeprovisioned registers a callback invoked after a successful deprovision.
// The containers are gone at that point, so anything following them must stop:
// the log collector uses it to cancel the organization's tailers.
func (s *Service) OnDeprovisioned(fn func(orgID uint)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onDeprovisioned = fn
}

// notifyDeprovisioned runs the registered callback, if any.
func (s *Service) notifyDeprovisioned(orgID uint) {
	s.mu.Lock()
	fn := s.onDeprovisioned
	s.mu.Unlock()
	if fn != nil {
		fn(orgID)
	}
}

// NewService builds the provisioning service. recorder persists the audit
// entries of user-initiated switch changes; without it those changes fail
// closed instead of running unaudited.
func NewService(db *gorm.DB, pool *PortPool, orch Orchestrator, recorder audit.TxRecorder, logger *zap.Logger, cfg Config) *Service {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Service{
		db:       db,
		pool:     pool,
		orch:     orch,
		recorder: recorder,
		checker:  hostPortChecker,
		logger:   logger,
		cfg:      cfg,
	}
}

// SetPortChecker replaces the host port availability check. Tests use it to
// stay independent of the host's port state; nil restores the default.
func (s *Service) SetPortChecker(c PortChecker) {
	if c == nil {
		c = hostPortChecker
	}
	s.checker = c
}

// snapshot is the subset written to ServerGroup.ConfigSnapshot. It never
// contains the private key.
type snapshot struct {
	HbbsPort    uint16 `json:"hbbs_port"`      // 21115, NAT type test
	HbbsMain    uint16 `json:"hbbs_main_port"` // 21116, id registry (tcp and udp)
	HbbsWS      uint16 `json:"hbbs_ws_port"`   // 21118, web client websocket
	HbbrPort    uint16 `json:"hbbr_port"`      // 21117, relay
	HbbrWS      uint16 `json:"hbbr_ws_port"`   // 21119, web client relay websocket
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
}

// ErrProvisioningDisabled is returned when a queued job finds that the
// organization was deprovisioned after the job was enqueued.
var ErrProvisioningDisabled = errors.New("provisioning disabled for this organization")

// State is the provisioning switch plus the deployment it permits. Status is
// disabled when the operator turned provisioning off, otherwise it is pending
// (no deployment row yet) or the ServerGroup state.
type State struct {
	Enabled bool
	Status  string
}

// Switch-derived status values. Deployment statuses reuse the ServerGroup
// state constants so the API and the database never disagree.
const (
	StatusDisabled = "disabled"
	StatusPending  = "pending"
)

// State reports the provisioning switch and deployment status of an
// organization.
func (s *Service) State(ctx context.Context, orgID uint) (State, error) {
	if err := store.RequireOrgID(orgID); err != nil {
		return State{}, err
	}

	var org model.Organization
	if err := s.db.WithContext(ctx).
		Select("id", "provisioning_disabled").
		First(&org, orgID).Error; err != nil {
		return State{}, fmt.Errorf("load organization: %w", err)
	}
	if org.ProvisioningDisabled {
		return State{Enabled: false, Status: StatusDisabled}, nil
	}

	var row model.ServerGroup
	err := store.ScopedByOrg(s.db.WithContext(ctx), orgID).First(&row).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return State{Enabled: true, Status: StatusPending}, nil
	case err != nil:
		return State{}, fmt.Errorf("load server group: %w", err)
	}
	return State{Enabled: true, Status: row.State}, nil
}

// SetEnabled flips the organization's provisioning switch. Disabling removes
// the deployment first and records the intent in the same transaction as the
// audit entry; enabling only clears the intent and leaves the actual deploy to
// the provisioning queue. The second return value reports whether the stored
// state changed, so callers can skip both the audit fallback and the enqueue on
// an idempotent request.
func (s *Service) SetEnabled(ctx context.Context, orgID, actorID uint, enabled bool) (State, bool, error) {
	if err := store.RequireOrgID(orgID); err != nil {
		return State{}, false, err
	}
	if s.recorder == nil {
		return State{}, false, errors.New("provision: no audit recorder configured")
	}
	// Hold the organization lock across the read, the container removal and the
	// transaction: a deploy must not allocate a row between the removal and the
	// flag commit, because that row's container would escape the removal.
	unlock := s.lockOrg(orgID)
	defer unlock()

	current, err := s.State(ctx, orgID)
	if err != nil {
		return State{}, false, err
	}
	if current.Enabled == enabled {
		// A repeated disable is not a pure no-op: a deployment that was
		// persisted concurrently with the first disable can still be running
		// while the flag already says disabled. Taking it down here is what makes
		// the switch self-healing instead of a permanently stuck no-op.
		if !enabled {
			if cleaned, cerr := s.cleanupLateDeploymentLocked(ctx, orgID, actorID); cerr != nil || cleaned {
				return State{Enabled: false, Status: StatusDisabled}, cleaned, cerr
			}
		}
		return current, false, nil
	}

	// Container removal cannot join the database transaction, so it runs
	// first: a failed removal leaves the flag untouched (fail closed).
	var row, removed *model.ServerGroup
	deferred := false
	if !enabled {
		row, err = s.loadDeployment(orgID)
		if err != nil {
			return State{}, false, err
		}
		switch {
		case row == nil:
		case deferProvisioningCleanup(row):
			// An in-flight deploy still owns the containers. Deleting its row
			// would erase the only durable cleanup pointer if the rollback later
			// fails or the process stops; keep it and let the attempt fence
			// itself at persist, or a later disable clean it once it is stale.
			deferred = true
		default:
			if rerr := s.removeRow(ctx, row); rerr != nil {
				return State{}, false, rerr
			}
			removed = row
		}
	}

	err = s.db.Transaction(func(tx *gorm.DB) error {
		detail := map[string]any{"enabled": enabled, "removed_deployment": removed != nil}
		if removed != nil {
			if err := store.ScopedByOrg(tx, orgID).Delete(&model.ServerGroup{}, removed.ID).Error; err != nil {
				return err
			}
			detail["hbbs_port"] = removed.HbbsPort
			detail["hbbr_port"] = removed.HbbrPort
		}
		if deferred && row != nil {
			detail["state"] = row.State
			detail["deferred_cleanup"] = true
			detail["hbbs_port"] = row.HbbsPort
			detail["hbbr_port"] = row.HbbrPort
		}
		if err := tx.Model(&model.Organization{}).
			Where("id = ?", orgID).
			Update("provisioning_disabled", !enabled).Error; err != nil {
			return err
		}
		return s.recordTx(tx, audit.Entry{
			OrganizationID: orgID,
			ActorUserID:    actorID,
			Action:         "organization.provisioning.update",
			TargetType:     "organization",
			TargetID:       fmt.Sprint(orgID),
			Detail:         detail,
		})
	})
	if err != nil {
		if removed != nil {
			// The containers are gone but the flag did not commit: the row must
			// not keep claiming a deployment that no longer exists.
			s.markFailed(removed, err)
		}
		return State{}, false, err
	}
	if removed != nil {
		s.notifyDeprovisioned(orgID)
	}

	// A deploy that persisted between the pre-check and the flag commit may have
	// handed the containers to a deployed row; take that one down now. Fresh
	// provisioning rows are left to their in-flight attempt.
	if !enabled {
		if _, cerr := s.cleanupLateDeploymentLocked(ctx, orgID, actorID); cerr != nil {
			return State{}, true, cerr
		}
	}

	state, err := s.State(ctx, orgID)
	if err != nil {
		return State{}, true, err
	}
	return state, true, nil
}

// recordTx writes one audit entry inside the caller's transaction; a missing
// recorder is a wiring error and must abort the mutation.
func (s *Service) recordTx(tx *gorm.DB, entry audit.Entry) error {
	if s.recorder == nil {
		return errors.New("provision: no audit recorder configured")
	}
	return s.recorder.RecordTx(tx, entry)
}

// cleanupLateDeploymentLocked removes a row that a concurrent deploy persisted
// after the organization was already disabled. It writes its own audit entry
// because the deployment removal is a real state change, not a no-op. Callers
// must hold the organization lock.
func (s *Service) cleanupLateDeploymentLocked(ctx context.Context, orgID, actorID uint) (bool, error) {
	row, err := s.loadDeployment(orgID)
	if err != nil {
		return false, err
	}
	if row == nil {
		return false, nil
	}
	if deferProvisioningCleanup(row) {
		// The in-flight deploy still owns the containers and will clean them up
		// when it fences itself at persist.
		return false, nil
	}
	if err := s.removeRow(ctx, row); err != nil {
		return false, err
	}

	err = s.db.Transaction(func(tx *gorm.DB) error {
		if err := store.ScopedByOrg(tx, orgID).Delete(&model.ServerGroup{}, row.ID).Error; err != nil {
			return err
		}
		return s.recordTx(tx, audit.Entry{
			OrganizationID: orgID,
			ActorUserID:    actorID,
			Action:         "organization.provisioning.update",
			TargetType:     "organization",
			TargetID:       fmt.Sprint(orgID),
			Detail: map[string]any{
				"enabled":            false,
				"removed_deployment": true,
				"hbbs_port":          row.HbbsPort,
				"hbbr_port":          row.HbbrPort,
			},
		})
	})
	if err != nil {
		s.markFailed(row, err)
		return false, err
	}
	s.notifyDeprovisioned(orgID)
	s.logger.Warn("removed a deployment that raced with the provisioning switch",
		zap.Uint("org_id", orgID))
	return true, nil
}

// ProvisionForOrg provisions an organization on behalf of an explicit request.
// It clears an earlier deprovision, so a deliberate removal can be followed by a
// deliberate re-deploy.
func (s *Service) ProvisionForOrg(ctx context.Context, orgID uint) (*model.ServerGroup, error) {
	if err := store.RequireOrgID(orgID); err != nil {
		return nil, err
	}
	// Clearing the flag shares the organization lock with the switch; a disable
	// that wins afterwards makes provision's allocation check fail instead of
	// deploying against the operator's intent.
	unlock := s.lockOrg(orgID)
	err := s.setProvisioningDisabled(orgID, false)
	unlock()
	if err != nil {
		return nil, err
	}
	return s.provision(ctx, orgID)
}

// ProvisionQueued provisions an organization from the worker queue. Unlike an
// explicit request it honours an existing deprovision: the job may have been
// enqueued before the operator removed the deployment, and running it would
// silently undo the removal.
func (s *Service) ProvisionQueued(ctx context.Context, orgID uint) (*model.ServerGroup, error) {
	if err := store.RequireOrgID(orgID); err != nil {
		return nil, err
	}
	var org model.Organization
	if err := s.db.WithContext(ctx).
		Select("id", "provisioning_disabled").
		First(&org, orgID).Error; err != nil {
		return nil, fmt.Errorf("load organization: %w", err)
	}
	if org.ProvisioningDisabled {
		return nil, ErrProvisioningDisabled
	}
	return s.provision(ctx, orgID)
}

// setProvisioningDisabled flips the deprovision marker. The write is detached
// from the caller context: bookkeeping must not depend on the caller still being
// around.
func (s *Service) setProvisioningDisabled(orgID uint, disabled bool) error {
	if err := s.db.Model(&model.Organization{}).
		Where("id = ?", orgID).
		Update("provisioning_disabled", disabled).Error; err != nil {
		return fmt.Errorf("update provisioning state: %w", err)
	}
	return nil
}

// provision allocates ports, generates keys, deploys and persists the result.
// Any failure releases the ports and removes the containers.
func (s *Service) provision(ctx context.Context, orgID uint) (*model.ServerGroup, error) {
	// Allocation shares the organization lock with the switch: a disable either
	// sees the row and removes it, or commits first and makes this check fail.
	unlock := s.lockOrg(orgID)
	row, err := s.pool.Allocate(orgID)
	if err == nil {
		var org model.Organization
		if lerr := s.db.Select("id", "provisioning_disabled").First(&org, orgID).Error; lerr != nil {
			s.release(row)
			err = fmt.Errorf("load organization: %w", lerr)
		} else if org.ProvisioningDisabled {
			s.release(row)
			err = ErrProvisioningDisabled
		}
	}
	unlock()
	if err != nil {
		return nil, err
	}

	// Ports are a host resource shared with everything else on the machine.
	// Failing here keeps the rollback path out of the picture (no container
	// exists yet) and names the occupied port instead of leaving an opaque
	// docker run error; the released block is retried by the reconciler.
	if conflict := s.checkBlock(row.HbbsPort); conflict != nil {
		s.release(row)
		return nil, fmt.Errorf("provision: %w: %s", ErrPortConflict, conflict.String())
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

	deployCtx, cancelDeploy := context.WithTimeout(ctx, deployTimeout)
	deployErr := s.orch.Deploy(deployCtx, spec)
	cancelDeploy()
	if deployErr != nil {
		s.rollbackFailedDeploy(ctx, row, spec, deployErr)
		return nil, fmt.Errorf("deploy hbbs/hbbr: %w", deployErr)
	}

	snap, err := json.Marshal(snapshot{
		HbbsPort:    row.HbbsPort,
		HbbsMain:    row.HbbsPort + 1,
		HbbsWS:      row.HbbsPort + 2,
		HbbrPort:    row.HbbrPort,
		HbbrWS:      row.HbbrPort + 1,
		PublicKey:   keys.PublicKey,
		Fingerprint: keys.Fingerprint,
	})
	if err != nil {
		s.rollbackFailedDeploy(ctx, row, spec, err)
		return nil, fmt.Errorf("snapshot config: %w", err)
	}

	// Persisting the deployment and re-reading the switch in one transaction
	// closes the ordering where a disable commits while the containers start:
	// the row update only lands if the flag is still false at that instant.
	unlock = s.lockOrg(orgID)
	persistErr := s.db.Transaction(func(tx *gorm.DB) error {
		var org model.Organization
		if err := tx.Select("id", "provisioning_disabled").First(&org, orgID).Error; err != nil {
			return fmt.Errorf("load organization: %w", err)
		}
		if org.ProvisioningDisabled {
			return ErrProvisioningDisabled
		}
		res := store.ScopedByOrg(tx, orgID).Model(&model.ServerGroup{}).
			Where("id = ?", row.ID).
			Updates(map[string]any{
				"pub_key":         keys.PublicKey,
				"fingerprint":     keys.Fingerprint,
				"config_snapshot": string(snap),
				"state":           model.ServerGroupDeployed,
				"last_error":      "",
			})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			// The row was deleted while the deploy was running.
			return ErrProvisioningDisabled
		}
		return nil
	})
	unlock()
	if persistErr != nil {
		// A failed or vanished row means the fresh containers must not outlive
		// their record; the flag was disabled or the database is inconsistent.
		s.rollbackFailedDeploy(ctx, row, spec, persistErr)
		return nil, fmt.Errorf("persist server group: %w", persistErr)
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

// PendingOrgIDs returns organizations after the given cursor that have no
// server group row, meaning provisioning never reached a worker: the queue was
// full at creation time, or the process stopped after the organization was
// committed.
//
// Organizations that were deliberately deprovisioned are excluded: removing the
// server group on purpose must not be undone by the reconciler.
//
// Results are ordered by id and capped by limit, so callers page through a
// backlog with the cursor. The second return value is the id of the last
// organization examined; passing it back as afterID continues the scan, and 0
// means the scan reached the end of the table and should restart.
func (s *Service) PendingOrgIDs(ctx context.Context, afterID uint, limit int) ([]uint, uint, error) {
	var all []uint
	query := s.db.WithContext(ctx).
		Model(&model.Organization{}).
		Where("provisioning_disabled = ?", false).
		Where("id > ?", afterID).
		Order("id")
	if limit > 0 {
		query = query.Limit(limit)
	}
	if err := query.Pluck("id", &all).Error; err != nil {
		return nil, 0, fmt.Errorf("list organizations: %w", err)
	}
	if len(all) == 0 {
		return nil, 0, nil
	}

	var provisioned []uint
	// Port allocations are a host-level resource, so the lookup spans tenants.
	// WithoutTenantScope must be applied after WithContext: it derives from the
	// current statement context, and a later WithContext would drop the marker.
	if err := store.WithoutTenantScope(s.db.WithContext(ctx)).
		Model(&model.ServerGroup{}).
		Pluck("organization_id", &provisioned).Error; err != nil {
		return nil, 0, fmt.Errorf("list server groups: %w", err)
	}
	seen := make(map[uint]struct{}, len(provisioned))
	for _, id := range provisioned {
		seen[id] = struct{}{}
	}

	missing := make([]uint, 0, len(all))
	for _, id := range all {
		if _, ok := seen[id]; ok {
			continue
		}
		missing = append(missing, id)
	}
	return missing, all[len(all)-1], nil
}

// loadDeployment returns the organization's server group row, if any.
func (s *Service) loadDeployment(orgID uint) (*model.ServerGroup, error) {
	var row model.ServerGroup
	err := store.ScopedByOrg(s.db, orgID).First(&row).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("load server group: %w", err)
	}
	return &row, nil
}

// removeRow stops a loaded deployment's containers without touching the
// database. A failed removal marks the row failed and keeps it, so the ports
// stay reserved and a later retry still has a cleanup pointer.
func (s *Service) removeRow(ctx context.Context, row *model.ServerGroup) error {
	name := fmt.Sprintf("panel-org-%d", row.OrganizationID)
	if err := s.orch.Remove(cleanupContext(ctx), name); err != nil {
		s.markFailed(row, fmt.Errorf("remove deployment: %w", err))
		return fmt.Errorf("remove deployment: %w", err)
	}
	return nil
}

// deferProvisioningCleanup reports whether the row still belongs to a deploy
// that may be creating containers right now. Deleting such a row would erase
// the only durable pointer to those containers.
func deferProvisioningCleanup(row *model.ServerGroup) bool {
	return row != nil && row.State == model.ServerGroupProvisioning &&
		time.Since(row.UpdatedAt) < staleProvisioningGrace
}

// removeDeployment stops the organization's containers. A nil row with a nil
// error means nothing was deployed. A failed removal keeps the row in the
// failed state (the ports stay reserved) and returns the error.
func (s *Service) removeDeployment(ctx context.Context, orgID uint) (*model.ServerGroup, error) {
	row, err := s.loadDeployment(orgID)
	if err != nil || row == nil {
		return nil, err
	}
	if err := s.removeRow(ctx, row); err != nil {
		return nil, err
	}
	return row, nil
}

// Deprovision removes the deployment and frees the ports.
func (s *Service) Deprovision(ctx context.Context, orgID uint) error {
	if err := store.RequireOrgID(orgID); err != nil {
		return err
	}
	// The switch and the explicit deprovision must not interleave their
	// container removal and row deletion.
	unlock := s.lockOrg(orgID)
	defer unlock()

	row, err := s.removeDeployment(ctx, orgID)
	if err != nil {
		return err
	}
	if row == nil {
		// Nothing is deployed yet, but the intent still has to stop the
		// reconciler from provisioning this organization later.
		return s.setProvisioningDisabled(orgID, true)
	}

	// Persist the deprovision intent together with the row deletion: otherwise
	// the reconciler would see an organization without a server group and
	// deploy it again.
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := store.ScopedByOrg(tx, orgID).Delete(&model.ServerGroup{}, row.ID).Error; err != nil {
			return err
		}
		return tx.Model(&model.Organization{}).
			Where("id = ?", orgID).
			Update("provisioning_disabled", true).Error
	}); err != nil {
		return err
	}
	s.notifyDeprovisioned(orgID)
	return nil
}

// rollbackFailedDeploy removes the containers of a failed deploy only while
// the row still identifies that deployment. Container names are per
// organization, so a disable followed by a re-enable can hand the name to a
// newer deployment; that deployment must not be torn down by the old attempt.
func (s *Service) rollbackFailedDeploy(ctx context.Context, row *model.ServerGroup, spec InstanceSpec, cause error) {
	unlock := s.lockOrg(row.OrganizationID)
	defer unlock()

	var current model.ServerGroup
	err := store.ScopedByOrg(s.db, row.OrganizationID).First(&current).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		// Our row is gone and no newer deployment exists yet: the containers
		// still belong to this attempt.
	case err != nil:
		s.logger.Warn("rollback skipped: cannot verify deployment ownership",
			zap.Uint("org_id", row.OrganizationID), zap.Error(err))
		return
	case current.ID != row.ID:
		s.logger.Info("rollback skipped: a newer deployment owns the containers",
			zap.Uint("org_id", row.OrganizationID),
			zap.Uint("old_id", row.ID), zap.Uint("current_id", current.ID))
		return
	}
	s.failAndCleanup(ctx, row, spec, cause)
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
