package logquery

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// ExportLimit caps one CSV export. It matches the audit export bound so the
// console has one rule to explain to operators.
const ExportLimit = 1000

// Filter narrows a log listing. All fields are optional and combine with AND.
type Filter struct {
	DeviceID   *uint
	RustdeskID string
	From       *time.Time
	To         *time.Time
}

// Service reads the client-reported logs back for the console.
type Service struct {
	db *gorm.DB
}

// NewService builds the read side.
func NewService(db *gorm.DB) *Service { return &Service{db: db} }

// Connections returns one page of connection logs visible to the viewer.
// Visibility follows the audit scope: global sees the organization, individual
// sees only devices it owns. A zero user id in individual scope sees nothing —
// it must never widen into a global read.
func (s *Service) Connections(ctx context.Context, orgID uint, viewer audit.Viewer, f Filter, page, pageSize int) ([]model.ConnectionLog, int64, error) {
	query := s.connectionsQuery(ctx, orgID, viewer, f)
	if query == nil {
		return nil, 0, nil
	}
	page, pageSize = audit.NormalizePagination(page, pageSize)

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("count connection logs: %w", err)
	}
	var rows []model.ConnectionLog
	if err := query.Order("started_at DESC").Order("id DESC").
		Offset((page - 1) * pageSize).Limit(pageSize).Find(&rows).Error; err != nil {
		return nil, 0, fmt.Errorf("list connection logs: %w", err)
	}
	return rows, total, nil
}

// FileLogs is Connections for transfer records.
func (s *Service) FileLogs(ctx context.Context, orgID uint, viewer audit.Viewer, f Filter, page, pageSize int) ([]model.FileLog, int64, error) {
	query := s.fileLogsQuery(ctx, orgID, viewer, f)
	if query == nil {
		return nil, 0, nil
	}
	page, pageSize = audit.NormalizePagination(page, pageSize)

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("count file logs: %w", err)
	}
	var rows []model.FileLog
	if err := query.Order("created_at DESC").Order("id DESC").
		Offset((page - 1) * pageSize).Limit(pageSize).Find(&rows).Error; err != nil {
		return nil, 0, fmt.Errorf("list file logs: %w", err)
	}
	return rows, total, nil
}

// ExportConnections returns at most ExportLimit rows, newest first.
func (s *Service) ExportConnections(ctx context.Context, orgID uint, viewer audit.Viewer, f Filter) ([]model.ConnectionLog, error) {
	query := s.connectionsQuery(ctx, orgID, viewer, f)
	if query == nil {
		return nil, nil
	}
	var rows []model.ConnectionLog
	if err := query.Order("id DESC").Limit(ExportLimit).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("export connection logs: %w", err)
	}
	return rows, nil
}

// ExportFileLogs is ExportConnections for transfer records.
func (s *Service) ExportFileLogs(ctx context.Context, orgID uint, viewer audit.Viewer, f Filter) ([]model.FileLog, error) {
	query := s.fileLogsQuery(ctx, orgID, viewer, f)
	if query == nil {
		return nil, nil
	}
	var rows []model.FileLog
	if err := query.Order("id DESC").Limit(ExportLimit).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("export file logs: %w", err)
	}
	return rows, nil
}

func (s *Service) connectionsQuery(ctx context.Context, orgID uint, viewer audit.Viewer, f Filter) *gorm.DB {
	query := store.ScopedByOrg(s.db.WithContext(ctx), orgID).Model(&model.ConnectionLog{})
	query = applyFilter(query, f, "started_at")
	return applyViewer(query, s.db, orgID, viewer)
}

func (s *Service) fileLogsQuery(ctx context.Context, orgID uint, viewer audit.Viewer, f Filter) *gorm.DB {
	query := store.ScopedByOrg(s.db.WithContext(ctx), orgID).Model(&model.FileLog{})
	query = applyFilter(query, f, "created_at")
	return applyViewer(query, s.db, orgID, viewer)
}

func applyFilter(query *gorm.DB, f Filter, timeColumn string) *gorm.DB {
	if f.DeviceID != nil {
		query = query.Where("device_id = ?", *f.DeviceID)
	}
	if f.RustdeskID != "" {
		query = query.Where("rustdesk_id = ?", f.RustdeskID)
	}
	if f.From != nil {
		query = query.Where(timeColumn+" >= ?", f.From.UTC())
	}
	if f.To != nil {
		query = query.Where(timeColumn+" <= ?", f.To.UTC())
	}
	return query
}

// applyViewer adds the audit-scope predicate. A nil return means "visible
// nothing" and the caller answers an empty page without touching the database.
func applyViewer(query *gorm.DB, db *gorm.DB, orgID uint, viewer audit.Viewer) *gorm.DB {
	if viewer.Scope == model.AuditScopeGlobal {
		return query
	}
	if viewer.UserID == 0 {
		return nil
	}
	// Unscoped keeps historical logs attributable after the device is
	// soft-deleted; the owner at deletion time still sees its evidence.
	owned := store.ScopedByOrg(db, orgID).Unscoped().Model(&model.Device{}).
		Select("id").Where("owner_user_id = ?", viewer.UserID)
	return query.Where("device_id IN (?)", owned)
}

// Prune deletes connection and file logs older than each organization's
// audit_retention_days. Zero means keep forever, matching the audit rows'
// semantics. These records are evidence, not an archive: unlike audit rows they
// are not written to JSONL first, so the cutoff is the only bound.
func Prune(ctx context.Context, db *gorm.DB, now time.Time) (int64, error) {
	var orgs []model.Organization
	if err := db.WithContext(ctx).Select("id", "audit_retention_days").
		Where("audit_retention_days > 0").Order("id").Find(&orgs).Error; err != nil {
		return 0, err
	}
	var removed int64
	for _, org := range orgs {
		cutoff := now.UTC().AddDate(0, 0, -org.AuditRetentionDays)
		for _, mdl := range []any{&model.ConnectionLog{}, &model.FileLog{}} {
			res := store.ScopedByOrg(db.WithContext(ctx), org.ID).
				Where("created_at < ?", cutoff).Delete(mdl)
			if res.Error != nil {
				return removed, fmt.Errorf("prune client logs for organization %d: %w", org.ID, res.Error)
			}
			removed += res.RowsAffected
		}
	}
	return removed, nil
}
