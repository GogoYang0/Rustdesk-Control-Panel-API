package api_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func seedLogDevice(t *testing.T, h *harness, orgID int64, rustdeskID string, owner uint) model.Device {
	t.Helper()
	dev := model.Device{
		OrganizationID: uint(orgID),
		RustdeskID:     rustdeskID,
		Name:           rustdeskID,
		OwnerUserID:    &owner,
	}
	require.NoError(t, store.ScopedByOrg(h.db.DB, uint(orgID)).Create(&dev).Error)
	return dev
}

func TestLogQuery_ListAndExport(t *testing.T) {
	h, orgID, _, _, member, ownerToken, adminToken, memberToken := m4Org(t)
	dev := seedLogDevice(t, h, orgID, "700001", member.ID)
	require.NoError(t, store.ScopedByOrg(h.db.DB, uint(orgID)).Create(&model.ConnectionLog{
		OrganizationID: uint(orgID),
		DeviceID:       dev.ID,
		RustdeskID:     dev.RustdeskID,
		ConnID:         5,
		SessionID:      5,
		IP:             "203.0.113.5",
		Status:         model.ConnectionLogStatusOpen,
		StartedAt:      time.Now().UTC().Add(-time.Hour),
	}).Error)

	base := "/api/v1/orgs/" + itoa(orgID) + "/connection-logs"
	w := h.do(t, http.MethodGet, base, nil, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var page struct {
		Items []struct {
			Id         int64  `json:"id"`
			RustdeskId string `json:"rustdesk_id"`
			Status     string `json:"status"`
		} `json:"items"`
		Total int64 `json:"total"`
	}
	decodeData(t, w, &page)
	require.EqualValues(t, 1, page.Total)
	require.Len(t, page.Items, 1)
	require.Equal(t, "700001", page.Items[0].RustdeskId)
	require.Equal(t, model.ConnectionLogStatusOpen, page.Items[0].Status)

	// A member holds device.read only; audit.read is not granted.
	w = h.do(t, http.MethodGet, base, nil, memberToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// The owner sees the organization through the global scope.
	w = h.do(t, http.MethodGet, base, nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = h.do(t, http.MethodGet, base+"/export", nil, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Contains(t, w.Header().Get("Content-Type"), "text/csv")
	body := w.Body.String()
	require.Contains(t, body, "started_at,ended_at,status,rustdesk_id,device_id")
	require.Contains(t, body, "700001")
	require.Contains(t, body, "203.0.113.5")

	var exportRows int64
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.AuditLog{}).
		Where("action = ?", "connection_log.export").Count(&exportRows).Error)
	require.EqualValues(t, 1, exportRows)

	// File logs answer the same way with an empty page.
	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/file-logs", nil, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var filePage struct {
		Total int64 `json:"total"`
	}
	decodeData(t, w, &filePage)
	require.Zero(t, filePage.Total)
}

func TestLogQuery_ExportTooLarge(t *testing.T) {
	h, orgID, _, _, member, _, adminToken, _ := m4Org(t)
	dev := seedLogDevice(t, h, orgID, "700002", member.ID)
	now := time.Now().UTC()
	rows := make([]model.ConnectionLog, 0, 1001)
	for i := 0; i < 1001; i++ {
		rows = append(rows, model.ConnectionLog{
			OrganizationID: uint(orgID),
			DeviceID:       dev.ID,
			RustdeskID:     dev.RustdeskID,
			ConnID:         int64(i + 1),
			SessionID:      int64(i + 1),
			Status:         model.ConnectionLogStatusClosed,
			StartedAt:      now,
		})
	}
	require.NoError(t, store.ScopedByOrg(h.db.DB, uint(orgID)).CreateInBatches(&rows, 200).Error)

	w := h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/connection-logs/export", nil, adminToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "narrow the filters")
}
