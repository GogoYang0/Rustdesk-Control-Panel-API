package audit

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// Audit rows are written with the server's local clock (time.Now), so their
// SQLite text carries a zone offset. A UTC query bound must still compare by
// instant; plain text comparison shifts the window by the server offset.
func TestTimeCondition_ComparesInstantsAcrossOffsets(t *testing.T) {
	dsn := fmt.Sprintf("file:audit_tz_%d?mode=memory&cache=shared", time.Now().UnixNano())
	st, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	require.NoError(t, st.DB.AutoMigrate(&model.Organization{}, &model.AuditLog{}))

	org := model.Organization{Name: "tz"}
	require.NoError(t, st.DB.Create(&org).Error)

	cst := time.FixedZone("CST", 8*60*60)
	rows := []model.AuditLog{
		{OrganizationID: org.ID, Seq: 1, Action: "before", CreatedAt: time.Date(2026, 10, 29, 10, 0, 0, 0, cst)},
		{OrganizationID: org.ID, Seq: 2, Action: "after", CreatedAt: time.Date(2026, 10, 29, 14, 0, 0, 0, cst)},
	}
	require.NoError(t, st.DB.Create(&rows).Error)

	cutoff := time.Date(2026, 10, 29, 5, 0, 0, 0, time.UTC) // 13:00 CST

	var before []model.AuditLog
	require.NoError(t, timeCondition(store.ScopedByOrg(st.DB, org.ID), "created_at", "<", cutoff).
		Order("seq").Find(&before).Error)
	require.Len(t, before, 1)
	require.Equal(t, "before", before[0].Action)

	var after []model.AuditLog
	require.NoError(t, timeCondition(store.ScopedByOrg(st.DB, org.ID), "created_at", ">=", cutoff).
		Order("seq").Find(&after).Error)
	require.Len(t, after, 1)
	require.Equal(t, "after", after[0].Action)
}
