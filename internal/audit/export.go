package audit

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"time"

	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// CSVLimit bounds one export; a wider interval must be narrowed by filters
// instead of streaming an unbounded amount of data.
const CSVLimit = 1000

// ErrExportTooLarge reports an export whose filtered row count exceeds CSVLimit.
var ErrExportTooLarge = errors.New("audit export exceeds the row limit; narrow the filters")

// ExportOpts carries the columns' lookup data for one export.
type ExportOpts struct {
	// Emails maps actor user ids to their account email for the actor_email
	// column; unknown ids yield an empty cell.
	Emails map[uint]string
}

// QueryAll returns up to limit rows for an export, refusing to truncate more.
// The same tenant scope, filters and visibility predicate as Query apply, and
// ordering matches the list (newest first).
func QueryAll(ctx context.Context, db *gorm.DB, orgID uint, f Filter, viewer Viewer, limit int) ([]model.AuditLog, error) {
	if orgID == 0 {
		return nil, fmt.Errorf("audit: organization is required")
	}
	if limit <= 0 || limit > CSVLimit {
		limit = CSVLimit
	}
	query := scopedQuery(ctx, db, orgID, f, viewer)
	if query == nil {
		return nil, nil
	}
	var rows []model.AuditLog
	if err := query.
		Order("created_at DESC").
		Order("id DESC").
		Limit(limit + 1).
		Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("export audit logs: %w", err)
	}
	if len(rows) > limit {
		return nil, ErrExportTooLarge
	}
	return rows, nil
}

// WriteCSV writes the audit rows as CSV. Cells beginning with a formula trigger
// (= + - @) are prefixed with a single quote so spreadsheet software treats
// them as text instead of executing them (CSV formula injection).
func WriteCSV(w io.Writer, rows []model.AuditLog, emails map[uint]string) error {
	out := csv.NewWriter(w)
	if err := out.Write([]string{
		"created_at", "actor_user_id", "actor_email", "action",
		"target_type", "target_id", "detail",
	}); err != nil {
		return err
	}
	for _, row := range rows {
		record := []string{
			row.CreatedAt.UTC().Format(time.RFC3339),
			fmt.Sprint(row.ActorUserID),
			emails[row.ActorUserID],
			row.Action,
			row.TargetType,
			row.TargetID,
			row.Detail,
		}
		for i := range record {
			record[i] = escapeFormula(record[i])
		}
		if err := out.Write(record); err != nil {
			return err
		}
	}
	out.Flush()
	return out.Error()
}

// escapeFormula prefixes a leading formula trigger with a single quote. The
// escaped cell stays readable and the spreadsheet never evaluates it. Control
// prefixes (tab, CR, LF) are included: some spreadsheets strip them and then
// evaluate the remainder as a formula.
func escapeFormula(cell string) string {
	if cell == "" {
		return cell
	}
	switch cell[0] {
	case '=', '+', '-', '@', '\t', '\r', '\n':
		return "'" + cell
	default:
		return cell
	}
}
