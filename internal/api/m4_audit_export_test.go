package api_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func TestAuditExport_WritesCSVAndAudits(t *testing.T) {
	h, orgID, _, _, _, ownerToken, _, _ := m4Org(t)
	createRoleAPI(t, h, orgID, ownerToken, "export-a", []string{"audit.read"}, "global")

	w := h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/audit-logs/export?action=role.create", nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Contains(t, w.Header().Get("Content-Type"), "text/csv")
	require.Contains(t, w.Header().Get("Content-Disposition"), "attachment")
	body := w.Body.String()
	require.Contains(t, body, "created_at,actor_user_id,actor_email,action,target_type,target_id,detail")
	require.Contains(t, body, "role.create")
	require.Contains(t, body, "m4-owner@example.com", "the actor email column resolves the account")
	require.NotContains(t, body, "audit.export", "the export's own audit row is written after the snapshot")

	require.EqualValues(t, 1, countAudit(t, h, "action = ?", "audit.export"))
}

func TestAuditExport_EscapesFormulaInjection(t *testing.T) {
	h, orgID, _, _, _, ownerToken, _, _ := m4Org(t)

	// A row whose stored cells look like spreadsheet formulas (the action and
	// target are constrained elsewhere, so this models imported/historical data).
	require.NoError(t, h.db.DB.Create(&model.AuditLog{
		OrganizationID: uint(orgID),
		Seq:            9000,
		ActorUserID:    0,
		Action:         "=HYPERLINK(\"http://evil\")",
		TargetType:     "user",
		TargetID:       "@SUM(1)",
		CreatedAt:      time.Now().UTC(),
	}).Error)

	w := h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/audit-logs/export", nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	body := w.Body.String()
	require.Contains(t, body, "'=HYPERLINK")
	require.Contains(t, body, "'@SUM(1)")
	require.NotContains(t, body, ",=HYPERLINK")
}

func TestAuditExport_OverLimitAndIndividualScope(t *testing.T) {
	h, orgID, _, _, member, ownerToken, _, memberToken := m4Org(t)

	rows := make([]model.AuditLog, 1001)
	now := time.Now().UTC()
	for i := range rows {
		rows[i] = model.AuditLog{
			OrganizationID: uint(orgID),
			Seq:            uint64(1000 + i),
			ActorUserID:    member.ID,
			Action:         "bulk.noise",
			CreatedAt:      now.Add(time.Duration(i) * time.Second),
		}
	}
	require.NoError(t, h.db.DB.CreateInBatches(&rows, 200).Error)

	// More rows than the cap: the export refuses instead of truncating.
	w := h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/audit-logs/export?action=bulk.noise", nil, ownerToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "narrow the filters")

	// Individual scope exports only the viewer's own rows.
	roleID := createRoleAPI(t, h, orgID, ownerToken, "exporter", []string{"audit.read"}, "individual")
	w = h.do(t, http.MethodPatch, "/api/v1/orgs/"+itoa(orgID)+"/members/"+itoa(int64(member.ID)),
		map[string]any{"role_id": roleID}, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/audit-logs/export?action=organization.member.role", nil, memberToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "organization.member.role")

	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/audit-logs/export?action=role.create", nil, memberToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	// Header only: the role.create row was authored by the owner for a role target.
	require.Equal(t, 1, strings.Count(strings.TrimSpace(w.Body.String()), "\n")+1,
		"an individual export must not leak other actors' rows")
}

func TestAuditExport_TenantIsolation(t *testing.T) {
	h, orgID, _, _, _, ownerToken, _, _ := m4Org(t)
	otherOrg := createOrg(t, h, ownerToken, "export-other")
	// The same owner may read both organizations it owns, but the export of
	// another tenant's id is scoped by the path org.
	w := h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(otherOrg)+"/audit-logs/export", nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NotContains(t, w.Body.String(), "m4-org", "no rows of the first organization may appear")

	h.seedUser(t, "export-stranger@example.com", "password123")
	strangerToken := h.login(t, "export-stranger@example.com", "password123")
	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/audit-logs/export", nil, strangerToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// Store import keeps the fixture's audit rows visible to the owner of the
	// organization it created (sanity that the path org is what scopes reads).
	var count int64
	require.NoError(t, store.ScopedByOrg(h.db.DB, uint(orgID)).Model(&model.AuditLog{}).Count(&count).Error)
	require.NotZero(t, count)
}
