package compatapi_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func seedAuditDevice(t *testing.T, h *harness) model.Device {
	t.Helper()
	org := h.seedOrg(t, "audit-org")
	dev := model.Device{
		OrganizationID: org.ID,
		RustdeskID:     "700001",
		Name:           "pc",
		BoundUUID:      "uuid-1",
	}
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).Create(&dev).Error)
	return dev
}

func (h *harness) connLogs(t *testing.T) []model.ConnectionLog {
	t.Helper()
	var rows []model.ConnectionLog
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Order("id").Find(&rows).Error)
	return rows
}

func TestAuditConn_AcceptsAndDedupes(t *testing.T) {
	h := newHarness(t)
	dev := seedAuditDevice(t, h)
	body := map[string]any{
		"id": dev.RustdeskID, "uuid": dev.BoundUUID, "action": "new",
		"ip": "203.0.113.5", "conn_id": 42, "session_id": 7, "nonce": "n-1",
	}
	w := h.do(t, http.MethodPost, "/api/audit/conn", body, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// The client retries transport errors; the same nonce must be idempotent.
	w = h.do(t, http.MethodPost, "/api/audit/conn", body, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Len(t, h.connLogs(t), 1)

	closeBody := map[string]any{
		"id": dev.RustdeskID, "uuid": dev.BoundUUID, "action": "close",
		"ip": "203.0.113.5", "conn_id": 42, "session_id": 7, "nonce": "n-2",
	}
	w = h.do(t, http.MethodPost, "/api/audit/conn", closeBody, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	rows := h.connLogs(t)
	require.Len(t, rows, 1)
	require.Equal(t, model.ConnectionLogStatusClosed, rows[0].Status)
}

func TestAuditConn_RejectsWrongUUID(t *testing.T) {
	h := newHarness(t)
	dev := seedAuditDevice(t, h)
	w := h.do(t, http.MethodPost, "/api/audit/conn", map[string]any{
		"id": dev.RustdeskID, "uuid": "not-the-bound-uuid", "action": "new",
		"conn_id": 1, "session_id": 1, "nonce": "n-1",
	}, "")
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	require.Empty(t, h.connLogs(t))
}

func TestAuditFile_RequiresKnownDevice(t *testing.T) {
	h := newHarness(t)
	w := h.do(t, http.MethodPost, "/api/audit/file", map[string]any{
		"id": "404404404", "uuid": "whatever", "type": 0, "nonce": "f-1",
	}, "")
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
}

func TestAuditAlarm_WritesAuditRow(t *testing.T) {
	h := newHarness(t)
	dev := seedAuditDevice(t, h)
	w := h.do(t, http.MethodPost, "/api/audit/alarm", map[string]any{
		"id": dev.RustdeskID, "uuid": dev.BoundUUID, "typ": 1,
		"info": `{"message":"too many attempts"}`, "conn_id": 42, "nonce": "a-1",
	}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var rows []model.AuditLog
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Find(&rows).Error)
	require.Len(t, rows, 1)
	require.Equal(t, "client.alarm.exceed_thirty_attempts", rows[0].Action)
	require.Contains(t, rows[0].Detail, "too many attempts")
}

func TestAuditConn_RejectsMalformed(t *testing.T) {
	h := newHarness(t)
	dev := seedAuditDevice(t, h)
	w := h.do(t, http.MethodPost, "/api/audit/conn", map[string]any{
		"id": dev.RustdeskID, "uuid": dev.BoundUUID, "action": "new",
	}, "")
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
}
