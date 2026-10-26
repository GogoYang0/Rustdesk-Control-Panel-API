package compatapi_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func seedPendingDisconnect(t *testing.T, h *harness, orgID, deviceID uint) model.DeviceDisconnect {
	t.Helper()
	row := model.DeviceDisconnect{
		OrganizationID: orgID,
		DeviceID:       deviceID,
		Reason:         "test",
		RequestedBy:    1,
		Status:         model.DisconnectStatusPending,
		RequestedAt:    time.Now().UTC(),
		ExpiresAt:      time.Now().UTC().Add(15 * time.Minute),
	}
	require.NoError(t, store.ScopedByOrg(h.db.DB, orgID).Create(&row).Error)
	return row
}

// TestHeartbeat_DeliversDisconnect for the happy path: the pending request is
// fulfilled with exactly the connection ids the client reported.
func TestHeartbeat_DeliversDisconnect(t *testing.T) {
	h := newHarness(t)
	org, dev := loginHeartbeatDevice(t, h, "881001")
	seedPendingDisconnect(t, h, org.ID, dev.ID)

	w := h.do(t, http.MethodPost, "/api/heartbeat", map[string]any{
		"id": "881001", "uuid": "uuid-881001", "conns": []int{11, 12},
	}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	body := decodeCompatBody(t, w)
	require.Equal(t, []any{float64(11), float64(12)}, body["disconnect"])

	var rows []model.DeviceDisconnect
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).Find(&rows).Error)
	require.Len(t, rows, 1)
	require.Equal(t, model.DisconnectStatusFulfilled, rows[0].Status)
	require.Equal(t, 2, rows[0].ConnCount)
	require.NotNil(t, rows[0].FulfilledAt)

	// A fulfilled request is never repeated: the next heartbeat is clean even
	// though the client still reports the same connections.
	body = heartbeat(t, h, "881001", 0)
	require.NotContains(t, body, "disconnect")
}

// TestHeartbeat_NoConnsKeepsDisconnectPending: without live connections the
// client has nothing to drop, so the request must survive.
func TestHeartbeat_NoConnsKeepsDisconnectPending(t *testing.T) {
	h := newHarness(t)
	org, dev := loginHeartbeatDevice(t, h, "881002")
	seedPendingDisconnect(t, h, org.ID, dev.ID)

	body := heartbeat(t, h, "881002", 0)
	require.NotContains(t, body, "disconnect")

	var row model.DeviceDisconnect
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).First(&row).Error)
	require.Equal(t, model.DisconnectStatusPending, row.Status)

	// With connections reported the pending request fires.
	w := h.do(t, http.MethodPost, "/api/heartbeat", map[string]any{
		"id": "881002", "uuid": "uuid-881002", "conns": []int{5},
	}, "")
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, []any{float64(5)}, decodeCompatBody(t, w)["disconnect"])
}

// TestHeartbeat_IgnoresInvalidConnIDs: the id list comes from an unauthenticated
// body, so anything that is not a positive i32 is dropped instead of echoed
// back as a disconnect target.
func TestHeartbeat_IgnoresInvalidConnIDs(t *testing.T) {
	h := newHarness(t)
	org, dev := loginHeartbeatDevice(t, h, "881003")
	seedPendingDisconnect(t, h, org.ID, dev.ID)

	w := h.do(t, http.MethodPost, "/api/heartbeat", map[string]any{
		"id": "881003", "uuid": "uuid-881003",
		"conns": []any{-1, 0, "x", 3.5},
	}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	body := decodeCompatBody(t, w)
	require.NotContains(t, body, "disconnect")

	var row model.DeviceDisconnect
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).First(&row).Error)
	require.Equal(t, model.DisconnectStatusPending, row.Status)
}

// TestHeartbeat_DisconnectAndStrategyTogether: one response can carry both, and
// the client handles them independently.
func TestHeartbeat_DisconnectAndStrategyTogether(t *testing.T) {
	h := newHarness(t)
	org, dev := loginHeartbeatDevice(t, h, "881004")
	seedPendingDisconnect(t, h, org.ID, dev.ID)
	s := seedStrategy(t, h, org.ID, "Both", `{"enable-audio":"N"}`, 3, true)
	assignStrategyToDevice(t, h, org.ID, dev.ID, s.ID)

	w := h.do(t, http.MethodPost, "/api/heartbeat", map[string]any{
		"id": "881004", "uuid": "uuid-881004", "conns": []int{21}, "modified_at": 0,
	}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	body := decodeCompatBody(t, w)
	require.Equal(t, []any{float64(21)}, body["disconnect"])
	require.EqualValues(t, 3, body["modified_at"])
	strategy, ok := body["strategy"].(map[string]any)
	require.True(t, ok)
	options, ok := strategy["config_options"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "N", options["enable-audio"])
}
