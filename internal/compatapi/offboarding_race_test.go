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

// The re-check must be scoped to the session's organization, not merely to the
// user: a membership in another organization must not keep a session alive.
// This pins the (org, user) pairing — a user-only lookup would pass the two
// tests above but re-admit a removed member through an unrelated membership.
func TestSession_MembershipInAnotherOrgDoesNotAuthorize(t *testing.T) {
	h := newHarness(t)
	u := h.seedUser(t, "cross-org@example.com", "password123", true)
	orgA := h.seedOrg(t, "org-a")
	h.seedMembership(t, u.ID, orgA.ID)

	token, _ := h.login(t, "cross-org@example.com", "password123", "123456789", "uuid-cross")

	// The user keeps a membership, but only in another organization: the
	// session belongs to org A, so org B's membership must not keep it alive.
	orgB := h.seedOrg(t, "org-b")
	h.seedMembership(t, u.ID, orgB.ID)
	require.NoError(t, store.ScopedByOrg(h.db.DB, orgA.ID).
		Where("user_id = ?", u.ID).
		Delete(&model.Membership{}).Error)

	w := h.do(t, http.MethodGet, "/api/peers", nil, token)
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
}

// The token claims and the persisted session must describe the same identity:
// handlers scope their queries by the token's org/user, so authorizing as one
// identity while checking another must fail. Both users are members of the
// organization here, so only the consistency check can reject the request.
func TestSession_TokenIdentityMustMatchSession(t *testing.T) {
	h := newHarness(t)
	u := h.seedUser(t, "mismatch@example.com", "password123", true)
	other := h.seedUser(t, "other@example.com", "password123", true)
	org := h.seedOrg(t, "acme")
	h.seedMembership(t, u.ID, org.ID)
	h.seedMembership(t, other.ID, org.ID)

	token, _ := h.login(t, "mismatch@example.com", "password123", "123456789", "uuid-mismatch")

	// Point the session row at another member: the token still identifies the
	// first user, the session row now identifies the second.
	_, _, jti, err := h.issuer.ParseCompat(token)
	require.NoError(t, err)
	require.NoError(t, store.WithoutTenantScope(h.db.DB).
		Model(&model.CompatSession{}).
		Where("jti = ?", jti).
		Update("user_id", other.ID).Error)

	w := h.do(t, http.MethodGet, "/api/peers", nil, token)
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
