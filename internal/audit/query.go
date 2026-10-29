package audit

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// Filter carries the optional audit-log query parameters. Zero values mean
// "no filter"; From is inclusive and To is exclusive (UTC half-open interval).
type Filter struct {
	Action      string
	ActorUserID *uint
	TargetType  string
	TargetID    string
	From        *time.Time
	To          *time.Time
}

// Viewer describes who reads the audit trail. Scope global sees the whole
// organization; anything else (including a missing scope) is individual and
// fails closed to the caller's own entries.
type Viewer struct {
	Scope  string
	UserID uint
}

// Pagination bounds mirror the contract.
const (
	DefaultPageSize = 50
	MaxPageSize     = 200
)

// NormalizePagination clamps pager input instead of rejecting it: an oversized
// page is a client bug, not a 500.
func NormalizePagination(page, pageSize int) (int, int) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = DefaultPageSize
	}
	if pageSize > MaxPageSize {
		pageSize = MaxPageSize
	}
	return page, pageSize
}

// Visible reports whether a viewer may see one audit row. It mirrors the SQL
// predicate applied by Query; keeping both in one place prevents the list and
// its tests from disagreeing about "my own entries".
func Visible(scope string, viewerID uint, row model.AuditLog) bool {
	if scope == model.AuditScopeGlobal {
		return true
	}
	if viewerID == 0 {
		return false
	}
	if row.ActorUserID == viewerID {
		return true
	}
	return row.TargetType == "user" && row.TargetID == userTargetID(viewerID)
}

// Query returns one page of audit rows and the unpaginated total. Ordering is
// created_at descending with id descending as the tie-break, so pages stay
// stable when several rows share a timestamp.
func Query(ctx context.Context, db *gorm.DB, orgID uint, f Filter, viewer Viewer, page, pageSize int) ([]model.AuditLog, int64, error) {
	if orgID == 0 {
		return nil, 0, fmt.Errorf("audit: organization is required")
	}
	page, pageSize = NormalizePagination(page, pageSize)

	query := scopedQuery(ctx, db, orgID, f, viewer)
	if query == nil {
		return nil, 0, nil
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("count audit logs: %w", err)
	}

	var rows []model.AuditLog
	if err := query.
		Order("created_at DESC").
		Order("id DESC").
		Offset((page - 1) * pageSize).
		Limit(pageSize).
		Find(&rows).Error; err != nil {
		return nil, 0, fmt.Errorf("list audit logs: %w", err)
	}
	return rows, total, nil
}

// scopedQuery applies the tenant scope, the filters and the viewer's visibility
// predicate. A nil result means the viewer may see nothing (a zero user id in
// individual scope must not degrade into a global read).
func scopedQuery(ctx context.Context, db *gorm.DB, orgID uint, f Filter, viewer Viewer) *gorm.DB {
	query := store.ScopedByOrg(db.WithContext(ctx), orgID).Model(&model.AuditLog{})
	if f.Action != "" {
		query = query.Where("action = ?", f.Action)
	}
	if f.ActorUserID != nil {
		query = query.Where("actor_user_id = ?", *f.ActorUserID)
	}
	if f.TargetType != "" {
		query = query.Where("target_type = ?", f.TargetType)
	}
	if f.TargetID != "" {
		query = query.Where("target_id = ?", f.TargetID)
	}
	if f.From != nil {
		query = timeCondition(query, "created_at", ">=", *f.From)
	}
	if f.To != nil {
		query = timeCondition(query, "created_at", "<", *f.To)
	}
	if viewer.Scope != model.AuditScopeGlobal {
		if viewer.UserID == 0 {
			return nil
		}
		query = query.Where(
			"(actor_user_id = ? OR (target_type = ? AND target_id = ?))",
			viewer.UserID, "user", userTargetID(viewer.UserID),
		)
	}
	return query
}

// userTargetID renders the user id the way user-targeted audit rows store it
// (numeric string), so the SQL predicate and Visible agree on equality.
func userTargetID(userID uint) string {
	return strconv.FormatUint(uint64(userID), 10)
}
