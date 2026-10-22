package api_test

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/api"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func alertsPath(orgID int64) string {
	return "/api/v1/orgs/" + strconv.FormatInt(orgID, 10) + "/alerts"
}

type alertItem struct {
	Id        int64           `json:"id"`
	Kind      string          `json:"kind"`
	Severity  string          `json:"severity"`
	SessionId *int64          `json:"session_id"`
	DeviceId  *int64          `json:"device_id"`
	Detail    *map[string]any `json:"detail"`
	CreatedAt string          `json:"created_at"`
}

type alertListBody struct {
	Code string `json:"code"`
	Data struct {
		Items    []alertItem `json:"items"`
		Page     int         `json:"page"`
		PageSize int64       `json:"page_size"`
		Total    int64       `json:"total"`
	} `json:"data"`
}

func seedAlert(t *testing.T, h *harness, orgID int64, kind, severity string, createdAt time.Time) int64 {
	t.Helper()
	row := model.Alert{
		OrganizationID: uint(orgID),
		Kind:           kind,
		Severity:       severity,
		DetailJSON:     `{"limit":30}`,
		CreatedAt:      createdAt,
	}
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Create(&row).Error)
	return int64(row.ID)
}

// The alert list is member-readable; an outsider is 403 like everywhere else.
func TestAlert_PermissionMatrix(t *testing.T) {
	h := newTicketHarness(t)
	owner, orgID := seedOrgOwner(t, h, "alert-owner@example.com")
	member := seedOrgMember(t, h, orgID, "alert-member@example.com")

	seedAlert(t, h, orgID, model.AlertKindOutsideWindow, model.AlertSeverityInfo, fixedNow)

	w := h.do(t, http.MethodGet, alertsPath(orgID), nil, member)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	_, otherOrg := seedOrgOwner(t, h, "alert-outsider@example.com")
	w = h.do(t, http.MethodGet, alertsPath(otherOrg), nil, member)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	_ = owner
}

// Ordering is created_at descending (id as tiebreaker), with the standard
// page metadata.
func TestAlert_ListOrdering(t *testing.T) {
	h := newTicketHarness(t)
	owner, orgID := seedOrgOwner(t, h, "alert-order@example.com")

	first := seedAlert(t, h, orgID, model.AlertKindOutsideWindow, model.AlertSeverityInfo, fixedNow)
	second := seedAlert(t, h, orgID, model.AlertKindDurationExceeded, model.AlertSeverityCritical, fixedNow.Add(time.Minute))

	w := h.do(t, http.MethodGet, alertsPath(orgID), nil, owner)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var list alertListBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &list))
	require.Equal(t, int64(2), list.Data.Total)
	require.Len(t, list.Data.Items, 2)
	require.Equal(t, second, list.Data.Items[0].Id, "newest first")
	require.Equal(t, first, list.Data.Items[1].Id)

	// The detail JSON reaches the client as an object.
	require.NotNil(t, list.Data.Items[1].Detail)
	require.Equal(t, float64(30), (*list.Data.Items[1].Detail)["limit"])
}

// Severity is an enum and must be validated (the status lesson from task 6);
// kind is a free string filter; since is inclusive.
func TestAlert_ListFilters(t *testing.T) {
	h := newTicketHarness(t)
	owner, orgID := seedOrgOwner(t, h, "alert-filter@example.com")

	seedAlert(t, h, orgID, model.AlertKindOutsideWindow, model.AlertSeverityInfo, fixedNow)
	seedAlert(t, h, orgID, model.AlertKindDurationExceeded, model.AlertSeverityCritical, fixedNow.Add(time.Minute))

	// An unknown severity is a 400, not an empty 200.
	w := h.do(t, http.MethodGet, alertsPath(orgID)+"?severity=bogus", nil, owner)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	// Severity filter.
	w = h.do(t, http.MethodGet, alertsPath(orgID)+"?severity=critical", nil, owner)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var list alertListBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &list))
	require.Equal(t, int64(1), list.Data.Total)
	require.Equal(t, model.AlertKindDurationExceeded, list.Data.Items[0].Kind)

	// Kind filter.
	w = h.do(t, http.MethodGet, alertsPath(orgID)+"?kind=outside_window", nil, owner)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &list))
	require.Equal(t, int64(1), list.Data.Total)

	// Unknown kind is a valid free-string filter that matches nothing.
	w = h.do(t, http.MethodGet, alertsPath(orgID)+"?kind=nope", nil, owner)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &list))
	require.Equal(t, int64(0), list.Data.Total)

	// Since excludes older rows.
	w = h.do(t, http.MethodGet, alertsPath(orgID)+"?since="+fixedNow.Add(30*time.Second).UTC().Format(time.RFC3339Nano), nil, owner)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &list))
	require.Equal(t, int64(1), list.Data.Total)
}

// The polled list is audit-silent; the session tracker's own alerts are the
// record.
func TestAlert_ListAuditSilent(t *testing.T) {
	auditor := &countingAuditor{}
	h := newHarnessWith(t, func(d *api.Deps) {
		d.Auditor = auditor
		d.Now = func() time.Time { return fixedNow }
	})
	owner, orgID := seedOrgOwner(t, h, "alert-audit@example.com")

	auditor.reset()
	w := h.do(t, http.MethodGet, alertsPath(orgID), nil, owner)
	require.Equal(t, http.StatusOK, w.Code)
	require.Zero(t, auditor.entries, "polled reads stay silent")
}
