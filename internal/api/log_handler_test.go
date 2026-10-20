package api_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

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
