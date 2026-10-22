package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// Log kinds the session tracker acts on. Everything else from the collector is
// stored but does not touch sessions.
const (
	LogEventKindConn         = "conn"
	LogEventKindDisconnected = "disconnected"
)

// nativeAggregationWindow bounds how recently a session must have been active
// for a conn event to merge into it. An open session whose last activity is
// older than this is a stale remnant (its logs stopped arriving): the new
// connection gets its own session and the remnant is left for the idle
// sweeper, so one forgotten open row cannot swallow every later connection.
const nativeAggregationWindow = 30 * time.Second

// DefaultIdleWindow is how long an open session may go without activity
// before the idle sweeper closes it. Without this, a panel session whose logs
// stop arriving stays open forever and holds its concurrency slot.
const DefaultIdleWindow = 10 * time.Minute

// Timeline event kinds appended to a session's history.
const (
	SessionEventStarted      = "started"
	SessionEventConnected    = "connected"
	SessionEventDisconnected = "disconnected"
)

// LogEventInput is one collector event that references a device of the
// organization.
type LogEventInput struct {
	Kind       string
	OccurredAt time.Time
	// Detail carries the rule's capture groups for the session timeline; it
	// may be nil.
	Detail map[string]any
}

// AlertFilter narrows the alerts listing. All fields are optional.
type AlertFilter struct {
	Severity *string
	Kind     *string
	Since    *time.Time
	Page     int
	PageSize int
}

// NormalisedPagination applies the shared clamping rules.
func (f AlertFilter) NormalisedPagination() (page, pageSize int) {
	return normalisePage(f.Page, f.PageSize)
}

// RecordLogEvent feeds one collector event into the session tracker.
//
// kind=conn: an open session of the same device that was active within the
// aggregation window absorbs the event (panel sessions only get their
// last_activity_at refreshed — the panel traffic flows through the same
// hbbs/hbbr and is already policy-governed; recording it as native would
// double-count and alert-spam). Otherwise a new native session starts, and a
// connection outside the allowed window is alerted, never blocked (D10: the
// panel cannot cut native traffic anyway).
//
// kind=disconnected: the device's open session is closed with the disconnect
// reason, whatever its origin. A closed session is never reopened — a
// reconnect is a new session.
//
// The error is logged by the caller and never blocks event storage: the event
// is already persisted when this runs (C7 semantics).
func (s *Service) RecordLogEvent(ctx context.Context, orgID, deviceID uint, in LogEventInput) (*model.Session, error) {
	if orgID == 0 || deviceID == 0 {
		return nil, fmt.Errorf("%w: organization and device are required", ErrInvalidInput)
	}
	if in.OccurredAt.IsZero() {
		in.OccurredAt = s.now().UTC()
	}
	occurred := in.OccurredAt.UTC()

	switch in.Kind {
	case LogEventKindConn:
		return s.recordConnEvent(ctx, orgID, deviceID, occurred, in.Detail)
	case LogEventKindDisconnected:
		return s.recordDisconnectedEvent(ctx, orgID, deviceID, occurred)
	default:
		// file/error/other lines carry no session semantics.
		return nil, nil
	}
}

// ReportLogEvent adapts the service to the log collector's SessionRecorder
// interface: the collector hands over the parsed fields directly and treats an
// error as its own log line, never as a failed event (C7).
func (s *Service) ReportLogEvent(ctx context.Context, orgID, deviceID uint, kind string, at time.Time, detail map[string]any) error {
	_, err := s.RecordLogEvent(ctx, orgID, deviceID, LogEventInput{
		Kind:       kind,
		OccurredAt: at,
		Detail:     detail,
	})
	return err
}

// recordConnEvent merges the event into an active session or starts a native
// one. The organization lock serialises the check-then-insert so two events
// for the same device cannot both miss and create duplicate sessions; the
// collector feeds events in order, so the lock also keeps last_activity_at
// monotonic per session.
func (s *Service) recordConnEvent(ctx context.Context, orgID, deviceID uint, occurred time.Time, detail map[string]any) (*model.Session, error) {
	var (
		sess   model.Session
		outErr error
	)
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := lockOrganization(tx, orgID); err != nil {
			return err
		}

		dev, err := s.loadDevice(tx, orgID, deviceID)
		if err != nil {
			return err
		}

		// The most recent still-active session of this device.
		var open model.Session
		err = store.ScopedByOrg(tx, orgID).
			Where("device_id = ? AND status = ? AND COALESCE(last_activity_at, started_at) >= ?",
				deviceID, model.SessionStatusOpen, occurred.Add(-nativeAggregationWindow)).
			Order("id").
			First(&open).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("load open session: %w", err)
		}
		if err == nil {
			res := store.ScopedByOrg(tx, orgID).
				Model(&model.Session{}).
				Where("id = ? AND status = ?", open.ID, model.SessionStatusOpen).
				Update("last_activity_at", occurred)
			if res.Error != nil {
				return fmt.Errorf("refresh activity: %w", res.Error)
			}
			if open.Origin == model.SessionOriginNative {
				// The merge is timeline evidence for native sessions. Panel
				// sessions stay quiet: their events are the panel's own, and
				// one log line per heartbeat would bury the real history.
				if err := s.appendEvent(tx, orgID, open.ID, SessionEventConnected, occurred, detail); err != nil {
					return err
				}
			}
			outErr = nil
			sess = open
			return nil
		}

		// No active session: start a native one and evaluate the window once,
		// at start. Merged events do not re-evaluate — one violation, one
		// alert, or a busy session would flood the list.
		sess = model.Session{
			OrganizationID: orgID,
			DeviceID:       deviceID,
			RustdeskID:     dev.RustdeskID,
			Origin:         model.SessionOriginNative,
			Status:         model.SessionStatusOpen,
			StartedAt:      occurred,
			LastActivityAt: &occurred,
			CreatedAt:      occurred,
		}
		if err := tx.Create(&sess).Error; err != nil {
			return fmt.Errorf("create native session: %w", err)
		}
		if err := s.appendEvent(tx, orgID, sess.ID, SessionEventStarted, occurred, detail); err != nil {
			return err
		}

		limits, err := s.limits(tx, orgID)
		if err != nil {
			return err
		}
		if !limits.WithinWindow(occurred) {
			// D10: native traffic cannot be blocked, so the violation is a
			// warning-level alert — the connection is already running.
			if err := s.recordAlert(tx, orgID, &sess.ID, &deviceID, model.AlertKindOutsideWindow, model.AlertSeverityWarning, map[string]any{
				"occurred_at": occurred,
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &sess, outErr
}

// recordDisconnectedEvent closes the device's open session (any origin). The
// close half of a connection can arrive long after the start, so no
// aggregation window applies here — but only one open session is closed: a
// device should not have several, and if a stale one lingers the sweeper owns
// it.
func (s *Service) recordDisconnectedEvent(ctx context.Context, orgID, deviceID uint, occurred time.Time) (*model.Session, error) {
	var sess model.Session
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := lockOrganization(tx, orgID); err != nil {
			return err
		}

		err := store.ScopedByOrg(tx, orgID).
			Where("device_id = ? AND status = ?", deviceID, model.SessionStatusOpen).
			Order("started_at DESC").
			First(&sess).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// The close half of a connection whose start was never seen.
			sess = model.Session{}
			return nil
		}
		if err != nil {
			return fmt.Errorf("load open session: %w", err)
		}

		reason := model.SessionEndDisconnected
		res := store.ScopedByOrg(tx, orgID).
			Model(&model.Session{}).
			Where("id = ? AND status = ?", sess.ID, model.SessionStatusOpen).
			Updates(map[string]any{
				"status":     model.SessionStatusClosed,
				"ended_at":   occurred,
				"end_reason": reason,
				"revision":   gorm.Expr("revision + 1"),
				"updated_at": occurred,
			})
		if res.Error != nil {
			return fmt.Errorf("close session: %w", res.Error)
		}
		if res.RowsAffected != 1 {
			// Closed by a concurrent disconnect: nothing to do.
			sess = model.Session{}
			return nil
		}
		// Re-read inside the transaction so the caller sees the committed row.
		if err := store.ScopedByOrg(tx, orgID).First(&sess, sess.ID).Error; err != nil {
			return fmt.Errorf("reload closed session: %w", err)
		}
		return s.appendEvent(tx, orgID, sess.ID, SessionEventDisconnected, occurred, nil)
	})
	if err != nil {
		return nil, err
	}
	if sess.ID == 0 {
		return nil, nil
	}
	return &sess, nil
}

// CloseIdleSessions closes open sessions whose last activity (or start, when
// no activity was ever recorded) is older than the window, and reports how
// many rows it closed. It runs on the background scheduler and is always
// cross-tenant. Idle timeouts are not alerts: nothing was violated, the trail
// just went quiet.
func (s *Service) CloseIdleSessions(ctx context.Context, now time.Time, idle time.Duration) (int64, error) {
	if idle <= 0 {
		return 0, fmt.Errorf("%w: idle window must be positive", ErrInvalidInput)
	}
	cutoff := now.UTC().Add(-idle)
	return s.closeSweptSessions(ctx, model.SessionEndIdleTimeout,
		func(db *gorm.DB) *gorm.DB {
			return db.Where("status = ? AND COALESCE(last_activity_at, started_at) < ?",
				model.SessionStatusOpen, cutoff)
		}, now)
}

// ClosePolicyExceededSessions closes open sessions that ran past their
// organization's max_session_minutes and alerts each one (the real connection
// is not cut — the panel is not in the signalling path — so the alert and the
// closed row are the operator's only signals). Organizations without a
// duration policy are never swept: null means unlimited.
func (s *Service) ClosePolicyExceededSessions(ctx context.Context, now time.Time) (int64, error) {
	// Open sessions are few (the idle sweep keeps them bounded), so loading
	// them once and grouping in memory beats per-organization queries.
	var open []model.Session
	if err := store.WithoutTenantScope(s.db.WithContext(ctx)).
		Where("status = ?", model.SessionStatusOpen).
		Order("id").
		Find(&open).Error; err != nil {
		return 0, fmt.Errorf("load open sessions: %w", err)
	}
	if len(open) == 0 {
		return 0, nil
	}

	limitsByOrg := map[uint]Limits{}
	var total int64
	for _, sess := range open {
		limits, ok := limitsByOrg[sess.OrganizationID]
		if !ok {
			loaded, err := s.limits(s.db.WithContext(ctx), sess.OrganizationID)
			if err != nil {
				return total, err
			}
			limits = loaded
			limitsByOrg[sess.OrganizationID] = limits
		}
		if limits.MaxMinutes == nil {
			continue
		}
		deadline := sess.StartedAt.Add(time.Duration(*limits.MaxMinutes) * time.Minute)
		if !now.UTC().After(deadline) {
			continue
		}
		n, err := s.closeSweptSessions(ctx, model.SessionEndPolicyExceeded,
			func(db *gorm.DB) *gorm.DB {
				return db.Where("id = ? AND status = ?", sess.ID, model.SessionStatusOpen)
			}, now)
		if err != nil {
			return total, err
		}
		total += n
		if n > 0 {
			// One alert per sweep, written outside the closed transaction: the
			// sweep is idempotent (a closed row never matches again), so the
			// alert cannot duplicate.
			if err := s.recordAlert(s.db.WithContext(ctx), sess.OrganizationID, &sess.ID, &sess.DeviceID,
				model.AlertKindDurationExceeded, model.AlertSeverityCritical, map[string]any{
					"started_at":  sess.StartedAt,
					"max_minutes": *limits.MaxMinutes,
					"closed_at":   now.UTC(),
				}); err != nil {
				return total, err
			}
		}
	}
	return total, nil
}

// closeSweptSessions closes the sessions matched by scope and appends a
// timeline event per closed row.
func (s *Service) closeSweptSessions(ctx context.Context, reason string, scope func(*gorm.DB) *gorm.DB, now time.Time) (int64, error) {
	base := store.WithoutTenantScope(s.db.WithContext(ctx)).Model(&model.Session{})
	var ids []uint
	if err := scope(base).Pluck("id", &ids).Error; err != nil {
		return 0, fmt.Errorf("list sessions to close: %w", err)
	}
	if len(ids) == 0 {
		return 0, nil
	}

	res := store.WithoutTenantScope(s.db.WithContext(ctx)).
		Model(&model.Session{}).
		Where("id IN ? AND status = ?", ids, model.SessionStatusOpen).
		Updates(map[string]any{
			"status":     model.SessionStatusClosed,
			"ended_at":   now.UTC(),
			"end_reason": reason,
			"revision":   gorm.Expr("revision + 1"),
			"updated_at": now.UTC(),
		})
	if res.Error != nil {
		return 0, fmt.Errorf("close sessions: %w", res.Error)
	}
	for _, id := range ids {
		if err := s.appendEvent(store.WithoutTenantScope(s.db.WithContext(ctx)), 0, id, reason, now.UTC(), nil); err != nil {
			return res.RowsAffected, err
		}
	}
	return res.RowsAffected, nil
}

// appendEvent adds one timeline entry. orgID 0 means the caller already runs
// cross-tenant (the sweeps); the tenant column is then filled from the
// session row.
func (s *Service) appendEvent(tx *gorm.DB, orgID, sessionID uint, kind string, at time.Time, detail map[string]any) error {
	if orgID == 0 {
		var sess model.Session
		if err := store.WithoutTenantScope(tx).Select("organization_id").First(&sess, sessionID).Error; err != nil {
			return fmt.Errorf("load session org: %w", err)
		}
		orgID = sess.OrganizationID
	}
	detailJSON := "{}"
	if len(detail) > 0 {
		if b, err := json.Marshal(detail); err == nil {
			detailJSON = string(b)
		}
	}
	row := model.SessionEvent{
		OrganizationID: orgID,
		SessionID:      sessionID,
		Kind:           kind,
		At:             at,
		DetailJSON:     detailJSON,
	}
	if err := store.ScopedByOrg(tx, orgID).Create(&row).Error; err != nil {
		return fmt.Errorf("append session event: %w", err)
	}
	return nil
}

// recordAlert writes one policy-violation alert. Alerts are their own record:
// unlike domain mutations they are not additionally audited, or every sweep
// would write the same fact twice in two tables.
func (s *Service) recordAlert(tx *gorm.DB, orgID uint, sessionID, deviceID *uint, kind, severity string, detail map[string]any) error {
	detailJSON := "{}"
	if len(detail) > 0 {
		if b, err := json.Marshal(detail); err == nil {
			detailJSON = string(b)
		}
	}
	row := model.Alert{
		OrganizationID: orgID,
		SessionID:      sessionID,
		DeviceID:       deviceID,
		Kind:           kind,
		Severity:       severity,
		DetailJSON:     detailJSON,
		CreatedAt:      s.now().UTC(),
	}
	if err := store.ScopedByOrg(tx, orgID).Create(&row).Error; err != nil {
		return fmt.Errorf("record alert: %w", err)
	}
	return nil
}

// ListAlerts returns one page of the organization's alerts plus the total
// under the current filter. Ordering is created_at descending with id as the
// tiebreaker, so the newest alert is first.
func (s *Service) ListAlerts(ctx context.Context, orgID uint, f AlertFilter) ([]model.Alert, int64, error) {
	if orgID == 0 {
		return nil, 0, fmt.Errorf("%w: organization is required", ErrInvalidInput)
	}
	page, pageSize := f.NormalisedPagination()

	query := store.ScopedByOrg(s.db.WithContext(ctx), orgID).Model(&model.Alert{})
	if f.Severity != nil {
		query = query.Where("severity = ?", *f.Severity)
	}
	if f.Kind != nil {
		query = query.Where("kind = ?", *f.Kind)
	}
	if f.Since != nil {
		query = query.Where("created_at >= ?", f.Since.UTC())
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("count alerts: %w", err)
	}

	var items []model.Alert
	if err := query.
		Order("created_at DESC").
		Order("id DESC").
		Offset((page - 1) * pageSize).
		Limit(pageSize).
		Find(&items).Error; err != nil {
		return nil, 0, fmt.Errorf("list alerts: %w", err)
	}
	return items, total, nil
}
