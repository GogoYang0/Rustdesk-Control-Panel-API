package api_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// The collected events are listed newest first, honour the deviceId/level/since
// filters, clamp the limit to the contract range and never leak another
// organization's rows.
func TestListLogEvents_FiltersAndIsolation(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "logs@example.com", "password123")
	token := h.login(t, "logs@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "logs-org"}, token)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var orgResp struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &orgResp))
	orgID := uint(orgResp.Data.Id)

	// A foreign organization the caller is not a member of (created directly,
	// not through the API that would add the caller as owner).
	foreign := model.Organization{Name: "foreign-org"}
	require.NoError(t, h.db.DB.Create(&foreign).Error)

	device := model.Device{OrganizationID: orgID, RustdeskID: "111111111", Name: "pc1"}
	require.NoError(t, store.ScopedByOrg(h.db.DB, orgID).Create(&device).Error)

	base := time.Now().UTC().Add(-time.Hour)
	mk := func(org uint, deviceID *uint, level string, at time.Time) {
		require.NoError(t, store.ScopedByOrg(h.db.DB, org).Create(&model.LogEvent{
			OrganizationID: org,
			DeviceID:       deviceID,
			Source:         model.LogSourceHbbs,
			Level:          level,
			Kind:           model.LogKindConn,
			DetailJSON:     `{"raw":"line"}`,
			OccurredAt:     at,
		}).Error)
	}
	deviceID := device.ID
	mk(orgID, &deviceID, model.LogLevelInfo, base.Add(1*time.Minute))
	mk(orgID, &deviceID, model.LogLevelError, base.Add(2*time.Minute))
	mk(orgID, nil, model.LogLevelInfo, base.Add(3*time.Minute))
	mk(foreign.ID, nil, model.LogLevelError, base.Add(4*time.Minute))

	get := func(query string) []map[string]any {
		w := h.do(t, http.MethodGet,
			"/api/v1/orgs/"+itoa(int64(orgID))+"/log-events"+query, nil, token)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var resp struct {
			Data []map[string]any `json:"data"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		return resp.Data
	}

	// Newest first, the foreign organization excluded.
	all := get("")
	require.Len(t, all, 3)
	require.Equal(t, "info", all[0]["level"], "the no-device row is the newest")
	require.Equal(t, "error", all[1]["level"])
	require.Equal(t, "info", all[2]["level"])

	// level filter.
	errorsOnly := get("?level=error")
	require.Len(t, errorsOnly, 1)
	require.Equal(t, "error", errorsOnly[0]["level"])

	// deviceId filter.
	perDevice := get("?deviceId=" + itoa(int64(deviceID)))
	require.Len(t, perDevice, 2)
	for _, row := range perDevice {
		require.EqualValues(t, deviceID, row["device_id"])
	}

	// since filter: 90s after the base drops the oldest row and keeps the two
	// newest (at +2min and +3min).
	since := base.Add(90 * time.Second).Format(time.RFC3339)
	recent := get("?since=" + since)
	require.Len(t, recent, 2)

	// limit clamp: limit=0 becomes the minimum of 1.
	clamped := get("?limit=0")
	require.Len(t, clamped, 1)

	// Contract enum violations are rejected instead of silently returning an
	// empty list (the generated binder does not validate enums).
	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(int64(orgID))+"/log-events?level=bogus", nil, token)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(int64(orgID))+"/log-events?deviceId=0", nil, token)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	// A foreign organization is forbidden for this caller.
	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(int64(foreign.ID))+"/log-events", nil, token)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
}

// SQLite keeps time.Time as text and compares it lexicographically, so a
// cutoff carrying an offset ("09:00:00+08:00") does not order against a row
// stored as "02:00:00+00:00" even though the row is later. The handler
// normalises the cutoff to UTC before the comparison.
func TestListLogEvents_SinceComparesInstantsNotOffsets(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "tz@example.com", "password123")
	token := h.login(t, "tz@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "tz-org"}, token)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var orgResp struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &orgResp))
	orgID := uint(orgResp.Data.Id)

	// Rows are always stored as UTC (the collector normalises them).
	stored := time.Date(2026, 10, 20, 2, 0, 0, 0, time.UTC)
	require.NoError(t, store.ScopedByOrg(h.db.DB, orgID).Create(&model.LogEvent{
		OrganizationID: orgID,
		Source:         model.LogSourceHbbs,
		Level:          model.LogLevelInfo,
		Kind:           model.LogKindConn,
		DetailJSON:     `{"raw":"line"}`,
		OccurredAt:     stored,
	}).Error)

	// A cutoff one hour earlier, expressed in +08:00 (09:00+08:00 == 01:00Z):
	// the event must be included.
	w = h.do(t, http.MethodGet,
		"/api/v1/orgs/"+itoa(int64(orgID))+"/log-events?since=2026-10-20T09:00:00%2B08:00", nil, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp struct {
		Data []map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Len(t, resp.Data, 1, "since must compare instants, not the serialised offset")

	// A cutoff one hour later, also in +08:00 (11:00+08:00 == 03:00Z): the
	// event must be excluded.
	w = h.do(t, http.MethodGet,
		"/api/v1/orgs/"+itoa(int64(orgID))+"/log-events?since=2026-10-20T11:00:00%2B08:00", nil, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Empty(t, resp.Data)
}

// The endpoint used to require only membership. Raw hbbs/hbbr lines can carry
// IPs, client ids and paths, so it now requires audit.read and applies the
// role's audit scope; an individual viewer sees only its own devices and never
// unattributable (device_id NULL) rows.
func TestListLogEvents_RequiresAuditReadAndScopesIndividual(t *testing.T) {
	h := newHarness(t)
	owner := h.seedUser(t, "logs-owner@example.com", "password123")
	ownerToken := h.login(t, "logs-owner@example.com", "password123")
	member := h.seedUser(t, "logs-member@example.com", "password123")
	memberToken := h.login(t, "logs-member@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "logs-scope-org"}, ownerToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var orgResp struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &orgResp))
	orgID := uint(orgResp.Data.Id)

	roles, err := authz.NewRoleService(h.db.DB).List(orgID)
	require.NoError(t, err)
	var memberRole model.Role
	for _, role := range roles {
		if role.Kind == model.RoleKindMember {
			memberRole = role
		}
	}
	require.NotZero(t, memberRole.ID)
	require.NoError(t, store.ScopedByOrg(h.db.DB, orgID).Create(&model.Membership{
		OrganizationID: orgID,
		UserID:         member.ID,
		RoleID:         memberRole.ID,
	}).Error)

	ownerID, memberID := owner.ID, member.ID
	ownerDevice := model.Device{OrganizationID: orgID, RustdeskID: "111000111", Name: "owner-pc", OwnerUserID: &ownerID}
	memberDevice := model.Device{OrganizationID: orgID, RustdeskID: "222000222", Name: "member-pc", OwnerUserID: &memberID}
	require.NoError(t, store.ScopedByOrg(h.db.DB, orgID).Create(&ownerDevice).Error)
	require.NoError(t, store.ScopedByOrg(h.db.DB, orgID).Create(&memberDevice).Error)

	base := time.Now().UTC().Add(-time.Hour)
	mk := func(deviceID *uint, level string) {
		require.NoError(t, store.ScopedByOrg(h.db.DB, orgID).Create(&model.LogEvent{
			OrganizationID: orgID,
			DeviceID:       deviceID,
			Source:         model.LogSourceHbbs,
			Level:          level,
			Kind:           model.LogKindConn,
			DetailJSON:     `{"raw":"line"}`,
			OccurredAt:     base,
		}).Error)
	}
	mk(&ownerDevice.ID, model.LogLevelInfo)
	mk(&memberDevice.ID, model.LogLevelWarn)
	mk(nil, model.LogLevelError)

	// Plain member: membership alone is no longer enough.
	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(int64(orgID))+"/log-events", nil, memberToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// Delegated auditor with individual scope sees only its own device and not
	// the unattributable row.
	var auditor model.Role
	require.NoError(t, h.db.DB.Transaction(func(tx *gorm.DB) error {
		role, err := authz.NewRoleService(h.db.DB).CreateCustomTx(
			tx, orgID, "auditor", []string{authz.PermAuditRead}, model.AuditScopeIndividual)
		if err != nil {
			return err
		}
		auditor = *role
		return nil
	}))
	require.NoError(t, store.ScopedByOrg(h.db.DB, orgID).Model(&model.Membership{}).
		Where("user_id = ?", member.ID).Update("role_id", auditor.ID).Error)

	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(int64(orgID))+"/log-events", nil, memberToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var scoped struct {
		Data []map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &scoped))
	require.Len(t, scoped.Data, 1)
	require.EqualValues(t, memberDevice.ID, scoped.Data[0]["device_id"])

	// The owner keeps global visibility.
	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(int64(orgID))+"/log-events", nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var all struct {
		Data []map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &all))
	require.Len(t, all.Data, 3)
}
