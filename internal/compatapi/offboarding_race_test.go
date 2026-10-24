package compatapi_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// A compat session can be inserted after the membership was removed (login
// resolves the organization outside its transaction). Every consumer must
// therefore re-check the current membership instead of trusting session
// validity alone.
func TestSession_RemovedMembershipIsRejected(t *testing.T) {
	h := newHarness(t)
	u := h.seedUser(t, "removed@example.com", "password123", true)
	org := h.seedOrg(t, "acme")
	h.seedMembership(t, u.ID, org.ID)

	token, _ := h.login(t, "removed@example.com", "password123", "123456789", "uuid-removed")

	w := h.do(t, http.MethodGet, "/api/peers", nil, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).
		Where("user_id = ?", u.ID).
		Delete(&model.Membership{}).Error)

	w = h.do(t, http.MethodGet, "/api/peers", nil, token)
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
}

// The unauthenticated heartbeat path resolves a session by device identity; it
// must also verify that the session's user still belongs to the organization,
// otherwise a session issued after removal can keep refreshing the device.
func TestHeartbeat_RemovedMembershipDoesNotTouchDevice(t *testing.T) {
	h := newHarness(t)
	u := h.seedUser(t, "removed-hb@example.com", "password123", true)
	org := h.seedOrg(t, "acme")
	h.seedMembership(t, u.ID, org.ID)

	fixture := loadFixture(t, "heartbeat_request.json")
	h.login(t, "removed-hb@example.com", "password123",
		fixture["id"].(string), fixture["uuid"].(string))

	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).
		Where("user_id = ?", u.ID).
		Delete(&model.Membership{}).Error)

	w := h.do(t, http.MethodPost, "/api/heartbeat", fixture, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var dev model.Device
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).
		Where("rustdesk_id = ?", fixture["id"]).
		First(&dev).Error)
	require.Nil(t, dev.LastSeenAt, "a removed member must not refresh the device")

	var beats int64
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).
		Model(&model.DeviceHeartbeat{}).
		Where("device_id = ?", dev.ID).
		Count(&beats).Error)
	require.Zero(t, beats)
}
