package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// issueTicket creates a connection ticket for a device and returns its id and
// plaintext token.
func issueTicket(t *testing.T, h *harness, orgID, deviceID int64, token string) (int64, string) {
	t.Helper()
	w := h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/tickets",
		map[string]any{"device_id": deviceID}, token)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var resp struct {
		Data struct {
			Ticket struct {
				Id int64 `json:"id"`
			} `json:"ticket"`
			Token string `json:"token"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotZero(t, resp.Data.Ticket.Id)
	require.NotEmpty(t, resp.Data.Token)
	return resp.Data.Ticket.Id, resp.Data.Token
}

func TestDeviceDisable_BlocksLoginHeartbeatAndRedeem(t *testing.T) {
	h, orgID, _, _, _, ownerToken, adminToken, memberToken := m4Org(t)
	dev := createDevice(t, h, orgID, ownerToken, "workstation", "123456789")

	// The member logs in through the compat layer, claiming this device.
	token := compatLogin(t, h, "m4-member@example.com", "password123", "123456789", "uuid-device")
	w := h.do(t, http.MethodGet, "/api/peers", nil, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// A ticket issued before the disable must not be redeemable afterwards.
	ticketID, ticketToken := issueTicket(t, h, orgID, dev.Id, memberToken)

	devicePath := "/api/v1/orgs/" + itoa(orgID) + "/devices/" + itoa(dev.Id)
	w = h.do(t, http.MethodPatch, devicePath, map[string]any{"disabled": true}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var disabled deviceView
	decodeData(t, w, &disabled)
	require.True(t, disabled.Disabled)

	// The device's live compat session dies; new logins are refused.
	w = h.do(t, http.MethodGet, "/api/peers", nil, token)
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
	require.Equal(t, http.StatusForbidden,
		compatLoginCode(t, h, "m4-member@example.com", "password123", "123456789", "uuid-device"))

	// Management heartbeat is an explicit 409; the credential-free compat
	// heartbeat stays silent 200 so the client never sees an error it cannot act on.
	w = h.do(t, http.MethodPost, devicePath+"/heartbeat", map[string]any{}, adminToken)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	w = h.do(t, http.MethodPost, "/api/heartbeat", map[string]any{
		"id": "123456789", "uuid": "uuid-device-2", "ver": 1, "conns": []any{},
	}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// Redeeming the pre-disable ticket is refused.
	w = h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/tickets/"+itoa(ticketID)+"/redeem",
		map[string]string{"token": ticketToken}, memberToken)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())

	// A plain member cannot disable devices.
	w = h.do(t, http.MethodPatch, devicePath, map[string]any{"disabled": true}, memberToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// Restoring the device makes it usable again; its old session stays revoked.
	w = h.do(t, http.MethodPatch, devicePath, map[string]any{"disabled": false}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var restored deviceView
	decodeData(t, w, &restored)
	require.False(t, restored.Disabled)
	w = h.do(t, http.MethodPost, devicePath+"/heartbeat", map[string]any{}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	token = compatLogin(t, h, "m4-member@example.com", "password123", "123456789", "uuid-device")
	w = h.do(t, http.MethodGet, "/api/peers", nil, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	require.EqualValues(t, 1, countAudit(t, h, "action = ?", "device.disable"))
	require.EqualValues(t, 1, countAudit(t, h, "action = ?", "device.enable"))
}

func TestDeviceDisable_RepeatAndCrossTenant(t *testing.T) {
	h, orgID, _, _, _, ownerToken, adminToken, _ := m4Org(t)
	dev := createDevice(t, h, orgID, ownerToken, "station", "555555555")
	devicePath := "/api/v1/orgs/" + itoa(orgID) + "/devices/" + itoa(dev.Id)

	w := h.do(t, http.MethodPatch, devicePath, map[string]any{"disabled": true}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.do(t, http.MethodPatch, devicePath, map[string]any{"disabled": true}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.EqualValues(t, 1, countAudit(t, h, "action = ?", "device.disable"))

	// A device of another organization is a 404, not a cross-tenant write.
	otherOrg := createOrg(t, h, ownerToken, "device-other-org")
	w = h.do(t, http.MethodPatch, "/api/v1/orgs/"+itoa(otherOrg)+"/devices/"+itoa(dev.Id),
		map[string]any{"disabled": true}, ownerToken)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
}
