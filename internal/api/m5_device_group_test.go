package api_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// m5DeviceGroupView mirrors the DeviceGroup schema of contract 0.9.0.
type m5DeviceGroupView struct {
	Id        int64   `json:"id"`
	Name      string  `json:"name"`
	DeviceIds []int64 `json:"device_ids"`
}

// TestAccess_DeviceGroupAdminFlow covers the management path: create, assign a
// device, move it to another group (one device, one group), and delete the group
// which releases the device back to ungrouped.
func TestAccess_DeviceGroupAdminFlow(t *testing.T) {
	h, orgID, _, _, _, _, adminToken, memberToken := m4Org(t)
	base := "/api/v1/orgs/" + itoa(orgID) + "/device-groups"

	device := model.Device{OrganizationID: uint(orgID), RustdeskID: "500000001", Name: "box"}
	require.NoError(t, h.db.DB.Create(&device).Error)

	w := h.do(t, http.MethodPost, base, map[string]string{"name": "Servers"}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var servers m5DeviceGroupView
	decodeData(t, w, &servers)
	require.Equal(t, "Servers", servers.Name)
	require.Empty(t, servers.DeviceIds)

	w = h.do(t, http.MethodPut, base+"/"+itoa(servers.Id)+"/devices",
		map[string][]int64{"device_ids": {int64(device.ID)}}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var mutation struct {
		Added   int `json:"added"`
		Removed int `json:"removed"`
	}
	decodeData(t, w, &mutation)
	require.Equal(t, 1, mutation.Added)
	require.Zero(t, mutation.Removed)

	w = h.do(t, http.MethodPost, base, map[string]string{"name": "Lab"}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var lab m5DeviceGroupView
	decodeData(t, w, &lab)

	// Moving the same device into another group must detach it from the first.
	w = h.do(t, http.MethodPut, base+"/"+itoa(lab.Id)+"/devices",
		map[string][]int64{"device_ids": {int64(device.ID)}}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = h.do(t, http.MethodGet, base, nil, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var groups []m5DeviceGroupView
	decodeData(t, w, &groups)
	byID := map[int64]m5DeviceGroupView{}
	for _, group := range groups {
		byID[group.Id] = group
	}
	require.Empty(t, byID[servers.Id].DeviceIds, "moving a device must clear the previous group")
	require.Equal(t, []int64{int64(device.ID)}, byID[lab.Id].DeviceIds)

	// A missing device_ids field is malformed, never "release every device".
	w = h.do(t, http.MethodPut, base+"/"+itoa(lab.Id)+"/devices", map[string]any{}, adminToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	w = h.do(t, http.MethodDelete, base+"/"+itoa(lab.Id), nil, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var deleted struct {
		RemovedRules     int `json:"removed_rules"`
		UngroupedDevices int `json:"ungrouped_devices"`
	}
	decodeData(t, w, &deleted)
	require.Zero(t, deleted.RemovedRules)
	require.Equal(t, 1, deleted.UngroupedDevices)

	var reloaded model.Device
	require.NoError(t, store.ScopedByOrg(h.db.DB, uint(orgID)).First(&reloaded, device.ID).Error)
	require.Nil(t, reloaded.DeviceGroupID, "deleting the group must release the device")

	w = h.do(t, http.MethodGet, base, nil, memberToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
}
