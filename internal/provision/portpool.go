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

// PortPool allocates hbbs/hbbr port pairs.
//
// Allocation is a database insert: the unique indexes on hbbs_port and hbbr_port
// make a collision observable, and the allocator simply tries the next pair.
// Two instances therefore never hand out the same pair.
type PortPool struct {
	db    *gorm.DB
	start uint16
	end   uint16
}

// NewPortPool builds a pool covering [start, end] with a step of two ports.
func NewPortPool(db *gorm.DB, start, end uint16) *PortPool {
	return &PortPool{db: db, start: start, end: end}
}

// Allocate reserves a port pair for the organization and returns the pending
// row. The caller owns the row: it either finalises it after a successful
// deploy or deletes it to release the ports.
func (p *PortPool) Allocate(orgID uint) (*model.ServerGroup, error) {
	if err := store.RequireOrgID(orgID); err != nil {
		return nil, err
	}
	if p.start == 0 || p.end <= p.start {
		return nil, fmt.Errorf("invalid port range %d-%d", p.start, p.end)
	}

	var lastErr error
	for hbbs := uint32(p.start); hbbs+1 <= uint32(p.end); hbbs += 2 {
		row := model.ServerGroup{
			OrganizationID: orgID,
			HbbsPort:       uint16(hbbs),
			HbbrPort:       uint16(hbbs + 1),
			State:          model.ServerGroupProvisioning,
		}
		err := store.ScopedByOrg(p.db, orgID).Create(&row).Error
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
