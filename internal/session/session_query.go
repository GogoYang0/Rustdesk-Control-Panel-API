package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// ErrSessionNotFound reports a session id that does not exist in this
// organization.
var ErrSessionNotFound = errors.New("session not found")

// Pagination defaults and caps from the contract.
const (
	defaultSessionPageSize = 50
	maxSessionPageSize     = 200
	// maxSessionPage bounds the page number. Without it a page near the int64
	// limit makes (page-1)*pageSize overflow into a negative offset, which GORM
	// silently clamps to zero — the client would see a huge page number echoed
	// back with the first page's rows.
	maxSessionPage = 100_000
	// maxSessionEvents caps the timeline returned by SessionDetail. The earliest
	// events are kept: they are what an investigation needs first.
	maxSessionEvents = 200
)

// SessionFilter narrows a session listing. All fields are optional.
type SessionFilter struct {
	Origin   *string
	Status   *string
	DeviceID *uint
	Since    *time.Time
	Until    *time.Time
	Page     int
	PageSize int
}

// NormalisedPagination returns the page and page size actually applied, so the
// HTTP layer can echo them instead of repeating the clamping rules.
//
// Input is clamped rather than rejected: a pager that asks for page 0 or an
// oversized page is a client bug, not a 500.
func (f SessionFilter) NormalisedPagination() (page, pageSize int) {
	return normalisePage(f.Page, f.PageSize)
}

// normalisePage is the shared clamping rule behind every paginated listing in
// this package (sessions, approvals): page and size floors, the contract's
// size cap, and the page cap that keeps (page-1)*pageSize from overflowing.
func normalisePage(page, pageSize int) (int, int) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = defaultSessionPageSize
	}
	if pageSize > maxSessionPageSize {
		pageSize = maxSessionPageSize
	}
	if page > maxSessionPage {
		page = maxSessionPage
	}
	return page, pageSize
}

// ListSessions returns one page of the organization's sessions plus the
// unpaginated total.
//
// Ordering is started_at descending with id as the tiebreaker, so sessions that
// share a second do not reorder between pages.
func (s *Service) ListSessions(ctx context.Context, orgID uint, f SessionFilter) ([]model.Session, int64, error) {
	if orgID == 0 {
		return nil, 0, fmt.Errorf("%w: organization is required", ErrInvalidInput)
	}
	page, pageSize := f.NormalisedPagination()

	query := store.ScopedByOrg(s.db.WithContext(ctx), orgID).Model(&model.Session{})
	if f.Origin != nil {
		query = query.Where("origin = ?", *f.Origin)
	}
	if f.Status != nil {
		query = query.Where("status = ?", *f.Status)
	}
	if f.DeviceID != nil {
		query = query.Where("device_id = ?", *f.DeviceID)
	}
	// since/until are inclusive on both ends, as the contract states.
	if f.Since != nil {
		query = query.Where("started_at >= ?", f.Since.UTC())
	}
	if f.Until != nil {
		query = query.Where("started_at <= ?", f.Until.UTC())
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("count sessions: %w", err)
	}

	var items []model.Session
	if err := query.
		Order("started_at DESC").
		Order("id DESC").
		Offset((page - 1) * pageSize).
		Limit(pageSize).
		Find(&items).Error; err != nil {
		return nil, 0, fmt.Errorf("list sessions: %w", err)
	}
	return items, total, nil
}

// SessionDetail returns the session and its timeline. The timeline is capped at
// maxSessionEvents entries, earliest first, and truncated reports whether more
// exist.
func (s *Service) SessionDetail(ctx context.Context, orgID, sessionID uint) (*model.Session, []model.SessionEvent, bool, error) {
	if orgID == 0 || sessionID == 0 {
		return nil, nil, false, fmt.Errorf("%w: organization and session are required", ErrInvalidInput)
	}

	var sess model.Session
	if err := store.ScopedByOrg(s.db.WithContext(ctx), orgID).
		Where("id = ?", sessionID).
		First(&sess).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, false, ErrSessionNotFound
		}
		return nil, nil, false, fmt.Errorf("load session: %w", err)
	}

	// Read one past the cap: that extra row is what makes the truncated flag
	// truthful instead of guessed.
	var events []model.SessionEvent
	if err := store.ScopedByOrg(s.db.WithContext(ctx), orgID).
		Where("session_id = ?", sessionID).
		Order("at ASC").
		Order("id ASC").
		Limit(maxSessionEvents + 1).
		Find(&events).Error; err != nil {
		return nil, nil, false, fmt.Errorf("load session events: %w", err)
	}

	truncated := len(events) > maxSessionEvents
	if truncated {
		events = events[:maxSessionEvents]
	}
	return &sess, events, truncated, nil
}
