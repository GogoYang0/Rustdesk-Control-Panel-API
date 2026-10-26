package api_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func createStrategy(t *testing.T, h *harness, orgID int64, token, name string, options map[string]string) strategyView {
	t.Helper()
	w := h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/strategies", map[string]any{
		"name":           name,
		"config_options": options,
	}, token)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var view strategyView
	decodeData(t, w, &view)
	return view
}

func TestStrategyAssign_DeviceGroupAndMember(t *testing.T) {
	h, orgID, _, _, member, _, adminToken, _ := m4Org(t)
	s := createStrategy(t, h, orgID, adminToken, "Baseline", map[string]string{"enable-audio": "N"})
	dev := seedLogDevice(t, h, orgID, "910001", member.ID)
	grp := model.DeviceGroup{OrganizationID: uint(orgID), Name: "site-a"}
	require.NoError(t, store.ScopedByOrg(h.db.DB, uint(orgID)).Create(&grp).Error)

	// Device level.
	w := h.do(t, http.MethodPut, "/api/v1/orgs/"+itoa(orgID)+"/devices/"+itoa(int64(dev.ID))+"/strategy",
		map[string]any{"strategy_id": s.Id}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// The device list is where an operator checks the result.
	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/devices", nil, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var page struct {
		Items []struct {
			Id         int64  `json:"id"`
			StrategyId *int64 `json:"strategy_id"`
		} `json:"items"`
	}
	decodeData(t, w, &page)
	devices := page.Items
	var found bool
	for _, d := range devices {
		if d.Id == int64(dev.ID) {
			found = true
			require.NotNil(t, d.StrategyId)
			require.Equal(t, s.Id, *d.StrategyId)
		}
	}
	require.True(t, found)

	// Group level.
	w = h.do(t, http.MethodPut, "/api/v1/orgs/"+itoa(orgID)+"/device-groups/"+itoa(int64(grp.ID))+"/strategy",
		map[string]any{"strategy_id": s.Id}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var groupGroup []struct {
		Id         int64  `json:"id"`
		StrategyId *int64 `json:"strategy_id"`
	}
	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/device-groups", nil, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	decodeData(t, w, &groupGroup)
	require.Len(t, groupGroup, 1)
	require.NotNil(t, groupGroup[0].StrategyId)
	require.Equal(t, s.Id, *groupGroup[0].StrategyId)

	// Member level.
	w = h.do(t, http.MethodPut, "/api/v1/orgs/"+itoa(orgID)+"/members/"+itoa(int64(member.ID))+"/strategy",
		map[string]any{"strategy_id": s.Id}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var members []struct {
		UserId     int64  `json:"user_id"`
		StrategyId *int64 `json:"strategy_id"`
	}
	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/members", nil, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	decodeData(t, w, &members)
	for _, m := range members {
		if m.UserId == int64(member.ID) {
			require.NotNil(t, m.StrategyId)
			require.Equal(t, s.Id, *m.StrategyId)
			found = true
		}
	}
	require.True(t, found)

	// Explicit null clears the device-level assignment.
	w = h.do(t, http.MethodPut, "/api/v1/orgs/"+itoa(orgID)+"/devices/"+itoa(int64(dev.ID))+"/strategy",
		map[string]any{"strategy_id": nil}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var stored model.Device
	require.NoError(t, store.ScopedByOrg(h.db.DB, uint(orgID)).First(&stored, dev.ID).Error)
	require.Nil(t, stored.StrategyID)
}

func TestStrategyAssign_RequiresManagePermission(t *testing.T) {
	h, orgID, _, _, member, _, adminToken, memberToken := m4Org(t)
	s := createStrategy(t, h, orgID, adminToken, "Baseline", nil)
	dev := seedLogDevice(t, h, orgID, "910002", member.ID)

	w := h.do(t, http.MethodPut, "/api/v1/orgs/"+itoa(orgID)+"/devices/"+itoa(int64(dev.ID))+"/strategy",
		map[string]any{"strategy_id": s.Id}, memberToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
}

func TestStrategyAssign_Validation(t *testing.T) {
	h, orgID, _, _, member, _, adminToken, _ := m4Org(t)
	s := createStrategy(t, h, orgID, adminToken, "Baseline", nil)
	dev := seedLogDevice(t, h, orgID, "910003", member.ID)
	base := "/api/v1/orgs/" + itoa(orgID) + "/devices/" + itoa(int64(dev.ID)) + "/strategy"

	// A missing field must not be read as "clear".
	w := h.do(t, http.MethodPut, base, map[string]any{}, adminToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	// A zero/negative id is not a strategy.
	w = h.do(t, http.MethodPut, base, map[string]any{"strategy_id": 0}, adminToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	// Unknown device and foreign strategy are both 404.
	w = h.do(t, http.MethodPut, "/api/v1/orgs/"+itoa(orgID)+"/devices/999999/strategy",
		map[string]any{"strategy_id": s.Id}, adminToken)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())

	otherOrgID := createOrg(t, h, adminToken, "assign-other")
	foreign := createStrategy(t, h, otherOrgID, adminToken, "Foreign", nil)
	w = h.do(t, http.MethodPut, base, map[string]any{"strategy_id": foreign.Id}, adminToken)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String(), "a strategy from another tenant must read as missing")

	// The refused writes left no assignment behind.
	var stored model.Device
	require.NoError(t, store.ScopedByOrg(h.db.DB, uint(orgID)).First(&stored, dev.ID).Error)
	require.Nil(t, stored.StrategyID)
}
