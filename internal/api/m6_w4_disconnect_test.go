package api_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

type disconnectView struct {
	Id          int64   `json:"id"`
	DeviceId    int64   `json:"device_id"`
	Reason      string  `json:"reason"`
	Status      string  `json:"status"`
	ConnCount   int     `json:"conn_count"`
	FulfilledAt *string `json:"fulfilled_at"`
}

func TestDisconnect_RequestLifecycle(t *testing.T) {
	h, orgID, _, _, member, _, adminToken, _ := m4Org(t)
	dev := seedLogDevice(t, h, orgID, "990001", member.ID)
	base := "/api/v1/orgs/" + itoa(orgID) + "/devices/" + itoa(int64(dev.ID)) + "/disconnect"

	w := h.do(t, http.MethodPost, base, map[string]any{"reason": "suspected leak"}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var created disconnectView
	decodeData(t, w, &created)
	require.Equal(t, model.DisconnectStatusPending, created.Status)
	require.Equal(t, "suspected leak", created.Reason)
	require.Equal(t, int64(dev.ID), created.DeviceId)

	// A second request would stack a duplicate teardown on the same device.
	w = h.do(t, http.MethodPost, base, map[string]any{"reason": "again"}, adminToken)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())

	// The accepted request is audited once, by the service on its own
	// transaction. The refused duplicate is not a domain change, so it falls to
	// the middleware row — evidence that somebody tried twice, without a second
	// disconnect entry in the trail.
	var rows, refused int64
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.AuditLog{}).
		Where("action = ?", "device.disconnect.request").Count(&rows).Error)
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.AuditLog{}).
		Where("action = ? AND detail LIKE ?",
			"POST /api/v1/orgs/:orgId/devices/:deviceId/disconnect", `%"status":409%`).Count(&refused).Error)
	require.EqualValues(t, 1, rows)
	require.EqualValues(t, 1, refused)
}

func TestDisconnect_RequiresPermission(t *testing.T) {
	h, orgID, _, _, member, _, adminToken, memberToken := m4Org(t)
	dev := seedLogDevice(t, h, orgID, "990002", member.ID)
	base := "/api/v1/orgs/" + itoa(orgID) + "/devices/" + itoa(int64(dev.ID)) + "/disconnect"

	w := h.do(t, http.MethodPost, base, map[string]any{"reason": "nope"}, memberToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// admin holds device.disconnect through the built-in set.
	w = h.do(t, http.MethodPost, base, map[string]any{"reason": "ok"}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
}

func TestDisconnect_Validation(t *testing.T) {
	h, orgID, _, _, member, _, adminToken, _ := m4Org(t)
	dev := seedLogDevice(t, h, orgID, "990003", member.ID)
	base := "/api/v1/orgs/" + itoa(orgID) + "/devices/" + itoa(int64(dev.ID)) + "/disconnect"

	// An empty reason leaves no trace of why a session was cut.
	w := h.do(t, http.MethodPost, base, map[string]any{"reason": "   "}, adminToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	// Unknown device, and a device of another organization, are both 404.
	w = h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/devices/999999/disconnect",
		map[string]any{"reason": "x"}, adminToken)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())

	otherOrgID := createOrg(t, h, adminToken, "disconnect-other")
	w = h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(otherOrgID)+"/devices/"+itoa(int64(dev.ID))+"/disconnect",
		map[string]any{"reason": "x"}, adminToken)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
}
