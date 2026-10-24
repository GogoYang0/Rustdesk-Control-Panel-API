package audit_test

import (
	"bytes"
	"context"
	"encoding/csv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

func TestWriteCSV_EscapesFormulaCells(t *testing.T) {
	buf := &bytes.Buffer{}
	rows := []model.AuditLog{{
		ActorUserID: 7,
		Action:      "=HYPERLINK(1)",
		TargetType:  "user",
		TargetID:    "@1",
		Detail:      `{"note":"+cmd"}`,
		CreatedAt:   time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC),
	}}
	require.NoError(t, audit.WriteCSV(buf, rows, map[uint]string{7: "actor@example.com"}))

	records, err := csv.NewReader(strings.NewReader(buf.String())).ReadAll()
	require.NoError(t, err)
	require.Len(t, records, 2)
	require.Equal(t, []string{
		"created_at", "actor_user_id", "actor_email", "action",
		"target_type", "target_id", "detail",
	}, records[0])
	row := records[1]
	require.Equal(t, "'=HYPERLINK(1)", row[3], "formula cells must be prefixed")
	require.Equal(t, "'@1", row[5])
	require.Equal(t, "actor@example.com", row[2])
	require.Contains(t, buf.String(), "'=HYPERLINK(1)")
}

func TestWriteCSV_EscapesEveryTrigger(t *testing.T) {
	// Control prefixes are included: a spreadsheet may strip them and then
	// evaluate the remainder.
	for _, trigger := range []string{"=x", "+x", "-x", "@x", "\tx", "\rx", "\nx"} {
		buf := &bytes.Buffer{}
		require.NoError(t, audit.WriteCSV(buf, []model.AuditLog{{
			Action: trigger, CreatedAt: time.Now().UTC(),
		}}, nil))
		require.Contains(t, buf.String(), "'"+trigger, "trigger %q must be neutralized", trigger)
	}

	// Ordinary values stay untouched; an unknown actor has an empty email cell.
	buf := &bytes.Buffer{}
	require.NoError(t, audit.WriteCSV(buf, []model.AuditLog{{
		ActorUserID: 99, Action: "role.create", CreatedAt: time.Now().UTC(),
	}}, map[uint]string{}))
	require.Contains(t, buf.String(), "role.create")
	require.NotContains(t, buf.String(), "'role.create")
}

func TestQueryAll_RejectsOverLimit(t *testing.T) {
	st, org, _ := newQueryFixture(t)
	ctx := context.Background()
	base := time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC)

	rows := make([]model.AuditLog, audit.CSVLimit+1)
	for i := range rows {
		rows[i] = model.AuditLog{
			OrganizationID: org.ID,
			Seq:            uint64(i + 1),
			ActorUserID:    1,
			Action:         "bulk",
			CreatedAt:      base.Add(time.Duration(i) * time.Second),
		}
	}
	require.NoError(t, st.DB.CreateInBatches(&rows, 200).Error)

	_, err := audit.QueryAll(ctx, st.DB, org.ID, audit.Filter{}, audit.Viewer{Scope: model.AuditScopeGlobal}, audit.CSVLimit)
	require.ErrorIs(t, err, audit.ErrExportTooLarge)

	// Exactly at the limit is allowed.
	from := base.Add(time.Second)
	rowsAtLimit, err := audit.QueryAll(ctx, st.DB, org.ID,
		audit.Filter{From: &from}, audit.Viewer{Scope: model.AuditScopeGlobal}, audit.CSVLimit)
	require.NoError(t, err)
	require.Len(t, rowsAtLimit, audit.CSVLimit)
}
