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

// Log kinds the session tracker acts on, per the contract's session
// lifecycle:
//
//   - conn is a **connection event**: a session absorbs at most one of them
//     (recording a `connected` timeline row when it does). A second
//     connection event, whatever how recent, means a second connection —
//     merging them would hide a connection and with it its policy alerts.
//   - disconnected is a **connection end**: it closes the device's open
//     session.
//   - file and error are **activity events**: they refresh whatever is open
//     and never start a second session for an already-tracked connection.
//   - other is unclassified and touches no session.
const (
	LogEventKindConn         = model.LogKindConn
	LogEventKindDisconnected = model.LogKindDisconnected
)

// DefaultIdleWindow is how long an open session may go without activity
// before the idle sweeper closes it. Without this, a panel session whose logs
// stop arriving stays open forever and holds its concurrency slot.
const DefaultIdleWindow = 10 * time.Minute

// Timeline event kinds appended to a session's history. The sweep reasons
// (idle_timeout, policy_exceeded) reuse the end_reason strings as kinds.
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

// RecordLogEvent feeds one collector event into the session tracker, applying
// the contract's merge rules. It returns the session the event landed on (nil
// when the event touches no session) and never blocks event storage — the
// caller logs failures and moves on (C7 semantics).
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
	case model.LogKindFile, model.LogKindError:
		return s.recordActivityEvent(ctx, orgID, deviceID, occurred, in.Kind, in.Detail)
	default:
		// Unclassified lines carry no session semantics.
		return nil, nil
	}
}

// openCandidates loads the device's open sessions, oldest first.
func (s *Service) openCandidates(tx *gorm.DB, orgID, deviceID uint) ([]model.Session, error) {
	var candidates []model.Session
	err := store.ScopedByOrg(tx, orgID).
		Where("device_id = ? AND status = ?", deviceID, model.SessionStatusOpen).
		Order("id").
		Find(&candidates).Error
	if err != nil {
		return nil, fmt.Errorf("load open sessions: %w", err)
	}
	return candidates, nil
}

// absorbedConnIDs returns the subset of session ids that already absorbed a
// connection event, judged by the presence of a `connected` timeline row.
func absorbedConnIDs(tx *gorm.DB, orgID uint, sessionIDs []uint) (map[uint]bool, error) {
	absorbed := make(map[uint]bool, len(sessionIDs))
	if len(sessionIDs) == 0 {
		return absorbed, nil
	}
	var ids []uint
	err := store.ScopedByOrg(tx, orgID).
		Model(&model.SessionEvent{}).
		Where("session_id IN ? AND kind = ?", sessionIDs, SessionEventConnected).
		Distinct().
		Pluck("session_id", &ids).Error
	if err != nil {
		return nil, fmt.Errorf("load absorbed sessions: %w", err)
	}
	for _, id := range ids {
		absorbed[id] = true
	}
	return absorbed, nil
}

// refreshActivity moves a session's activity clock forward. The timestamp
// condition keeps the value monotonic: the two tailers (hbbs + hbbr) process
// lines concurrently, so an older event can be applied after a newer one, and
// a backwards last_activity_at would make the idle sweep fire early. Callers
// treat a false result as "the session was closed meanwhile", not as an
// error. (The interleaving itself is not reproducible on SQLite, which
// serialises writes locally — same recorded limitation as the row locks.)
func refreshActivity(tx *gorm.DB, orgID, sessionID uint, occurred time.Time) (bool, error) {
	res := store.ScopedByOrg(tx, orgID).
		Model(&model.Session{}).
		Where("id = ? AND status = ? AND (last_activity_at IS NULL OR last_activity_at < ?)",
			sessionID, model.SessionStatusOpen, occurred).
		Updates(map[string]any{
			"last_activity_at": occurred,
			"revision":         gorm.Expr("revision + 1"),
			"updated_at":       occurred,
		})
	if res.Error != nil {
		return false, fmt.Errorf("refresh activity: %w", res.Error)
	}
	return res.RowsAffected == 1, nil
}

// startNativeSession creates the native session the event starts and
// evaluates the time window once, at start. Merged events do not re-evaluate:
// one violation, one alert, or a busy session would flood the list.
// timelineKind is the session's first timeline row: for a conn event it is
// `connected` — that event IS the session's connection and occupies its
// single absorption slot; for an activity event it is `started`, because the
// connection itself was never observed.
func (s *Service) startNativeSession(tx *gorm.DB, orgID uint, dev *model.Device, deviceID uint, occurred time.Time, detail map[string]any, timelineKind string, evaluateWindow bool) (model.Session, error) {
	sess := model.Session{
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
		return model.Session{}, fmt.Errorf("create native session: %w", err)
	}
	if err := s.appendEvent(tx, orgID, sess.ID, timelineKind, occurred, detail); err != nil {
		return model.Session{}, err
	}

	if evaluateWindow {
		limits, err := s.limits(tx, orgID)
		if err != nil {
			return model.Session{}, err
		}
		if !limits.WithinWindow(occurred) {
			// D10: native traffic cannot be blocked, so the violation is a
			// warning-level alert — the connection is already running.
			if err := s.recordAlert(tx, orgID, &sess.ID, &deviceID, model.AlertKindOutsideWindow, model.AlertSeverityWarning, map[string]any{
				"occurred_at": occurred,
			}); err != nil {
				return model.Session{}, err
			}
		}
	}
	return sess, nil
}

// recordConnEvent applies the contract's connection-event rules: a session
// absorbs at most one connection event; everything else starts a new native
// session. The organization lock serialises the check-then-insert so two
// events for the same device cannot both miss and create duplicates.
func (s *Service) recordConnEvent(ctx context.Context, orgID, deviceID uint, occurred time.Time, detail map[string]any) (*model.Session, error) {
	var sess model.Session
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := lockOrganization(tx, orgID); err != nil {
			return err
		}
		dev, err := s.loadDevice(tx, orgID, deviceID)
		if err != nil {
			return err
		}

		candidates, err := s.openCandidates(tx, orgID, deviceID)
		if err != nil {
			return err
		}
		ids := make([]uint, 0, len(candidates))
		for _, c := range candidates {
			ids = append(ids, c.ID)
		}
		absorbed, err := absorbedConnIDs(tx, orgID, ids)
		if err != nil {
			return err
		}

		// Exactly one candidate that has not absorbed a connection event yet:
		// this event is that session's connection.
		unabsorbed := make([]model.Session, 0, 1)
		for _, c := range candidates {
			if !absorbed[c.ID] {
				unabsorbed = append(unabsorbed, c)
			}
		}
		if len(unabsorbed) == 1 {
			c := unabsorbed[0]
			if _, err := refreshActivity(tx, orgID, c.ID, occurred); err != nil {
				return err
			}
			// The connected timeline row is what marks the session as having
			// absorbed its one connection event, so it is written for panel
			// and native alike — without it the panel's absorption could not
			// be judged and a second connection would slip into the same
			// session. The panel difference is what is *not* written: no
			// alert, no further bookkeeping.
			if err := s.appendEvent(tx, orgID, c.ID, SessionEventConnected, occurred, detail); err != nil {
				return err
			}
			// For a native candidate this event is the first observed moment
			// of the connection, so the window is evaluated here too: the
			// session may have been started by an activity event, which does
			// not judge the window (an activity line is not a connection).
			if c.Origin == model.SessionOriginNative {
				limits, lerr := s.limits(tx, orgID)
				if lerr != nil {
					return lerr
				}
				if !limits.WithinWindow(occurred) {
					if err := s.recordAlert(tx, orgID, &c.ID, &deviceID, model.AlertKindOutsideWindow, model.AlertSeverityWarning, map[string]any{
						"occurred_at": occurred,
					}); err != nil {
						return err
					}
				}
			}
			sess = c
			return nil
		}

		// Zero candidates, or every candidate already absorbed its connection
		// event, or several at once (indeterminable): the contract prefers
		// over-recording a native session to hiding a connection.
		sess, err = s.startNativeSession(tx, orgID, dev, deviceID, occurred, detail, SessionEventConnected, true)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &sess, nil
}

// recordActivityEvent applies the contract's activity-event rules: with a
// single open candidate the event merges into it (panel refreshes silently,
// native also records the event); with several the event refreshes all of
// them and is recorded on the native session(s) — never "panel first", which
// would let the native session idle out and its duration alerts vanish; with
// none a native session starts.
func (s *Service) recordActivityEvent(ctx context.Context, orgID, deviceID uint, occurred time.Time, kind string, detail map[string]any) (*model.Session, error) {
	var (
		sess  model.Session
		found bool
	)
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := lockOrganization(tx, orgID); err != nil {
			return err
		}
		dev, err := s.loadDevice(tx, orgID, deviceID)
		if err != nil {
			return err
		}

		candidates, err := s.openCandidates(tx, orgID, deviceID)
		if err != nil {
			return err
		}
		if len(candidates) == 0 {
			// An activity event with no open session still marks a live
			// connection the tracker never saw start.
			sess, err = s.startNativeSession(tx, orgID, dev, deviceID, occurred, detail, SessionEventStarted, false)
			if err != nil {
				return err
			}
			found = true
			return nil
		}

		for _, c := range candidates {
			if _, err := refreshActivity(tx, orgID, c.ID, occurred); err != nil {
				return err
			}
		}
		if len(candidates) == 1 {
			sess = candidates[0]
			found = true
		}
		// The event itself is recorded on the native session(s) only.
		for _, c := range candidates {
			if c.Origin == model.SessionOriginNative {
				if err := s.appendEvent(tx, orgID, c.ID, kind, occurred, detail); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return &sess, nil
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
		func(tx *gorm.DB) *gorm.DB {
			return tx.Where("status = ? AND COALESCE(last_activity_at, started_at) < ?",
				model.SessionStatusOpen, cutoff)
		}, now, nil)
}

// ClosePolicyExceededSessions closes open sessions that ran past their
// organization's max_session_minutes and alerts each one (the real connection
// is not cut — the panel is not in the signalling path — so the alert and the
// closed row are the operator's only signals). Organizations without a
// duration policy are never swept: null means unlimited.
//
// Accepted behaviour under D10: the real connection keeps running, so its
// next log events start a fresh session, which will be closed and alerted
// again after another max_session_minutes. The contract prefers over-recording
// to silence; an unbounded session would otherwise never be visible.
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
			func(tx *gorm.DB) *gorm.DB {
				return tx.Where("id = ? AND status = ?", sess.ID, model.SessionStatusOpen)
			}, now,
			// Close and alert in one transaction: a close that commits
			// without its alert is a permanently lost critical signal, since
			// the closed row never matches the sweep again.
			func(tx *gorm.DB) error {
				return s.recordAlert(tx, sess.OrganizationID, &sess.ID, &sess.DeviceID,
					model.AlertKindDurationExceeded, model.AlertSeverityCritical, map[string]any{
						"started_at":  sess.StartedAt,
						"max_minutes": *limits.MaxMinutes,
						"closed_at":   now.UTC(),
					})
			})
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// closeSweptSessions closes the sessions matched by scope and appends a
// timeline event per closed row. Each row closes in its own transaction
// (close + optional alert + timeline), so a row closed concurrently by a
// disconnect never gets a forged sweep timeline: its update simply affects no
// rows and nothing is written.
func (s *Service) closeSweptSessions(ctx context.Context, reason string, scope func(*gorm.DB) *gorm.DB, now time.Time, afterClose func(*gorm.DB) error) (int64, error) {
	// Snapshot the matching ids cross-tenant; the per-row transaction
	// re-checks status, so a stale snapshot is safe.
	var ids []uint
	if err := scope(store.WithoutTenantScope(s.db.WithContext(ctx)).Model(&model.Session{})).
		Pluck("id", &ids).Error; err != nil {
		return 0, fmt.Errorf("list sessions to close: %w", err)
	}
	if len(ids) == 0 {
		return 0, nil
	}

	var total int64
	for _, id := range ids {
		err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			res := store.WithoutTenantScope(tx).
				Model(&model.Session{}).
				Where("id = ? AND status = ?", id, model.SessionStatusOpen).
				Updates(map[string]any{
					"status":     model.SessionStatusClosed,
					"ended_at":   now.UTC(),
					"end_reason": reason,
					"revision":   gorm.Expr("revision + 1"),
					"updated_at": now.UTC(),
				})
			if res.Error != nil {
				return fmt.Errorf("close session: %w", res.Error)
			}
			if res.RowsAffected != 1 {
				// Closed meanwhile (disconnect or a concurrent sweep): no
				// timeline, no alert.
				return nil
			}
			if err := s.appendEvent(tx, 0, id, reason, now.UTC(), nil); err != nil {
				return err
			}
			if afterClose != nil {
				return afterClose(tx)
			}
			return nil
		})
		if err != nil {
			return total, err
		}
		total++
	}
	return total, nil
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
