package provision

import (
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// ErrPortPoolExhausted is returned when no free port pair is left in the range.
var ErrPortPoolExhausted = errors.New("no free hbbs/hbbr port pair in the configured range")

// ErrAlreadyProvisioned is returned when the organization already has a
// deployed server group.
var ErrAlreadyProvisioned = errors.New("organization already provisioned")

// ErrProvisioningInProgress is returned when the organization has a pending or
// failed row that must be cleaned up first.
var ErrProvisioningInProgress = errors.New("organization has a pending provisioning record")

// PortPool allocates hbbs/hbbr port pairs.
//
// Allocation is a database insert: the unique indexes on hbbs_port and hbbr_port
// make a collision observable, and the allocator tries the next pair. Two
// instances therefore never hand out the same pair.
type PortPool struct {
	db    *gorm.DB
	start uint16
	end   uint16
}

// PortBlockSize is how many host ports one organization needs (see model.ServerGroup).
const PortBlockSize = 5

// hbbrPortOffset is where the hbbr sub-block starts inside the organization's
// five-port block, so HbbrPort is always HbbsPort+hbbrPortOffset. hbbs owns the
// first three host ports (21115, 21116 tcp/udp, 21118 websocket).
const hbbrPortOffset = 3

// NewPortPool builds a pool covering [start, end] in blocks of PortBlockSize.
func NewPortPool(db *gorm.DB, start, end uint16) *PortPool {
	return &PortPool{db: db, start: start, end: end}
}

// Allocate reserves a port pair for the organization and returns the pending
// row. The caller either finalises it after a successful deploy or deletes it to
// release the ports.
func (p *PortPool) Allocate(orgID uint) (*model.ServerGroup, error) {
	if err := store.RequireOrgID(orgID); err != nil {
		return nil, err
	}
	if p.start == 0 || p.end < p.start+PortBlockSize-1 {
		return nil, fmt.Errorf("invalid port range %d-%d", p.start, p.end)
	}

	// Distinguish an organization conflict from a port conflict: without this
	// check every create would collide on organization_id and the loop would
	// report a bogus "port pool exhausted" after scanning the whole range.
	var existing model.ServerGroup
	err := store.ScopedByOrg(p.db, orgID).First(&existing).Error
	switch {
	case err == nil && existing.State == model.ServerGroupDeployed:
		return nil, fmt.Errorf("%w", ErrAlreadyProvisioned)
	case err == nil:
		return nil, fmt.Errorf("%w: state=%s", ErrProvisioningInProgress, existing.State)
	case !errors.Is(err, gorm.ErrRecordNotFound):
		return nil, fmt.Errorf("look up server group: %w", err)
	}

	var lastErr error
	for base := uint32(p.start); base+PortBlockSize-1 <= uint32(p.end); base += PortBlockSize {
		overlap, err := p.blockOverlaps(uint16(base))
		if err != nil {
			return nil, err
		}
		if overlap {
			// A block can overlap without colliding on the two indexed columns
			// when provision.portStart changes after allocations exist
			// (21116..21120 vs 21117..21121). The host would bind some ports
			// twice, so the whole block is skipped.
			lastErr = fmt.Errorf("block %d-%d overlaps an existing allocation", base, base+PortBlockSize-1)
			continue
		}

		row := model.ServerGroup{
			OrganizationID: orgID,
			HbbsPort:       uint16(base),
			HbbrPort:       uint16(base + hbbrPortOffset),
			State:          model.ServerGroupProvisioning,
		}
		err = store.ScopedByOrg(p.db, orgID).Create(&row).Error
		if err == nil {
			return &row, nil
		}
		if !errors.Is(err, gorm.ErrDuplicatedKey) {
			return nil, fmt.Errorf("allocate ports: %w", err)
		}
		lastErr = err
	}
	return nil, fmt.Errorf("%w: %v", ErrPortPoolExhausted, lastErr)
}

// blockOverlaps reports whether the five-port block starting at base overlaps a
// block that is already reserved.
//
// Host ports are a machine-level resource, so this lookup spans tenants on
// purpose: the pool protects ports, not tenant data.
func (p *PortPool) blockOverlaps(base uint16) (bool, error) {
	var rows []model.ServerGroup
	if err := store.WithoutTenantScope(p.db).
		Select("hbbs_port", "hbbr_port").
		Find(&rows).Error; err != nil {
		return false, fmt.Errorf("list reserved port blocks: %w", err)
	}

	start := uint32(base)
	end := start + PortBlockSize - 1
	for _, r := range rows {
		rStart := uint32(r.HbbsPort)
		// hbbr publishes HbbrPort and HbbrPort+1; fall back to the full block
		// width for rows written by an older layout.
		rEnd := uint32(r.HbbrPort) + 1
		if rEnd < rStart+PortBlockSize-1 {
			rEnd = rStart + PortBlockSize - 1
		}
		if rStart <= end && start <= rEnd {
			return true, nil
		}
	}
	return false, nil
}
