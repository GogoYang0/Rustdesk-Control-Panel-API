package compatapi_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/compatapi"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// ── #39: offboarding kills the compat sessions ──────────────────────────────

// Revoking a user's sessions for one organization makes their compat token
// unusable there immediately: the management endpoints answer 401 and the
// credential-free heartbeat stops touching the device.
func TestRevokeOrgSessions_KillsCompatToken(t *testing.T) {
	h := newHarness(t)
	u := h.seedUser(t, "offboard@example.com", "password123", true)
	org := h.seedOrg(t, "acme")
	h.seedMembership(t, u.ID, org.ID)

	token, _ := h.login(t, "offboard@example.com", "password123", "333333333", "offboard-uuid")

	// Before revocation everything works.
	w := h.do(t, http.MethodGet, "/api/peers", nil, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// The offboarding path (membership removal, role downgrade) revokes.
	revoked, err := compatapi.RevokeOrgSessions(context.Background(), h.db.DB, org.ID, u.ID, time.Now())
	require.NoError(t, err)
	require.Equal(t, int64(1), revoked)

	// The management side is dead on the next request.
	w = h.do(t, http.MethodGet, "/api/peers", nil, token)
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())

	// And the credential-free heartbeat finds no live session.
	w = h.do(t, http.MethodPost, "/api/heartbeat", map[string]any{
		"id": "333333333", "uuid": "offboard-uuid",
	}, "")
	require.Equal(t, http.StatusOK, w.Code, "fire-and-forget stays 200")

	var dev model.Device
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).
		Where("rustdesk_id = ?", "333333333").First(&dev).Error)
	require.Nil(t, dev.LastSeenAt, "a revoked session must not drive the heartbeat")

	// A repeat logout on the already-revoked session is a plain 401 from the
	// session guard (logout sits behind requireSession): it neither revives
	// the session nor errors the server.
	w = h.do(t, http.MethodPost, "/api/logout", nil, token)
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())

	var count int64
	require.NoError(t, h.db.DB.Model(&model.CompatSession{}).
		Where("organization_id = ? AND revoked_at IS NOT NULL", org.ID).
		Count(&count).Error)
	require.Equal(t, int64(1), count)
}

// The revocation is scoped: the same user's session in another organization
// and another user's session in this organization stay alive.
func TestRevokeOrgSessions_ScopeLimited(t *testing.T) {
	h := newHarness(t)
	u := h.seedUser(t, "scope@example.com", "password123", true)
	orgA := h.seedOrg(t, "org-a")
	orgB := h.seedOrg(t, "org-b")
	h.seedMembership(t, u.ID, orgA.ID)
	h.seedMembership(t, u.ID, orgB.ID)
	other := h.seedUser(t, "other@example.com", "password123", true)
	h.seedMembership(t, other.ID, orgA.ID)

	// Two memberships require the #orgID selector on login (C16).
	_, _ = h.login(t, "scope@example.com#"+fmt.Sprint(orgA.ID), "password123", "", "")
	_, _ = h.login(t, "scope@example.com#"+fmt.Sprint(orgB.ID), "password123", "", "")
	_, _ = h.login(t, "other@example.com", "password123", "", "")

	revoked, err := compatapi.RevokeOrgSessions(context.Background(), h.db.DB, orgA.ID, u.ID, time.Now())
	require.NoError(t, err)
	require.Equal(t, int64(1), revoked, "only this user's row in this org")

	var aliveA, aliveB, aliveOther int64
	require.NoError(t, h.db.DB.Model(&model.CompatSession{}).
		Where("user_id = ? AND organization_id = ? AND revoked_at IS NULL", u.ID, orgB.ID).
		Count(&aliveB).Error)
	require.Equal(t, int64(1), aliveB, "the same user's other-org session survives")

	require.NoError(t, h.db.DB.Model(&model.CompatSession{}).
		Where("user_id = ? AND organization_id = ? AND revoked_at IS NULL", other.ID, orgA.ID).
		Count(&aliveOther).Error)
	require.Equal(t, int64(1), aliveOther, "another user's session in the same org survives")

	require.NoError(t, h.db.DB.Model(&model.CompatSession{}).
		Where("user_id = ? AND organization_id = ? AND revoked_at IS NULL", u.ID, orgA.ID).
		Count(&aliveA).Error)
	require.Equal(t, int64(0), aliveA)
}

// ── #40: binding generation ─────────────────────────────────────────────────

// A successful claim records the device's binding generation on the session,
// so later activity can be judged against the binding the session was issued
// under.
func TestLogin_RecordsBindingGeneration(t *testing.T) {
	h := newHarness(t)
	u := h.seedUser(t, "gen@example.com", "password123", true)
	org := h.seedOrg(t, "acme")
	h.seedMembership(t, u.ID, org.ID)

	_, _ = h.login(t, "gen@example.com", "password123", "444444444", "gen-uuid")

	var dev model.Device
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).
		Where("rustdesk_id = ?", "444444444").First(&dev).Error)
	require.NotZero(t, dev.BindingGeneration, "a claim advances the binding generation")

	var sess model.CompatSession
	require.NoError(t, h.db.DB.Where("device_id = ?", "444444444").First(&sess).Error)
	require.Equal(t, dev.BindingGeneration, sess.BindingGeneration,
		"the session snapshots the generation it was issued under")
}

// A session issued under an older binding generation must not drive the
// device after the binding moved on (reset and re-claim without deleting the
// row): its heartbeats are dropped and last_seen does not move.
func TestHeartbeat_StaleGenerationRejected(t *testing.T) {
	h := newHarness(t)
	u := h.seedUser(t, "stale@example.com", "password123", true)
	org := h.seedOrg(t, "acme")
	h.seedMembership(t, u.ID, org.ID)

	_, _ = h.login(t, "stale@example.com", "password123", "555555555", "stale-uuid")

	// One heartbeat under the current binding works.
	w := h.do(t, http.MethodPost, "/api/heartbeat", map[string]any{
		"id": "555555555", "uuid": "stale-uuid",
	}, "")
	require.Equal(t, http.StatusOK, w.Code)

	var dev model.Device
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).
		Where("rustdesk_id = ?", "555555555").First(&dev).Error)
	require.NotNil(t, dev.LastSeenAt)

	// The heartbeat coalescing window (30s) would swallow the next report,
	// which would make the stale session look rejected even without the
	// generation check. Pull last_seen back so the window lets it through.
	staleSeen := time.Now().Add(-2 * time.Hour)
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).Model(&model.Device{}).
		Where("id = ?", dev.ID).
		Update("last_seen_at", staleSeen).Error)

	firstSeen := staleSeen

	// The binding generation moves on without changing the uuid — e.g. an
	// administrator re-bind flow that re-issues the binding record. Only the
	// generation check can refuse the old session here; the uuid still
	// matches on purpose.
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).Model(&model.Device{}).
		Where("id = ?", dev.ID).
		Updates(map[string]any{
			"binding_generation": dev.BindingGeneration + 1,
		}).Error)

	// The old session's heartbeat must be dropped: its generation no longer
	// matches the device's.
	w = h.do(t, http.MethodPost, "/api/heartbeat", map[string]any{
		"id": "555555555", "uuid": "stale-uuid",
	}, "")
	require.Equal(t, http.StatusOK, w.Code, "fire-and-forget stays 200")

	var after model.Device
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).First(&after, dev.ID).Error)
	require.True(t, firstSeen.Equal(*after.LastSeenAt),
		"a stale-generation session must not move last_seen: got %v want %v", after.LastSeenAt, firstSeen)
}

// The sysinfo path enforces the same generation check.
func TestSysinfo_StaleGenerationRejected(t *testing.T) {
	h := newHarness(t)
	u := h.seedUser(t, "stale-sys@example.com", "password123", true)
	org := h.seedOrg(t, "acme")
	h.seedMembership(t, u.ID, org.ID)

	_, _ = h.login(t, "stale-sys@example.com", "password123", "666666667", "stale-sys-uuid")

	w := h.do(t, http.MethodPost, "/api/sysinfo", map[string]any{
		"id": "666666667", "uuid": "stale-sys-uuid",
	}, "")
	require.Equal(t, http.StatusOK, w.Code)

	var dev model.Device
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).
		Where("rustdesk_id = ?", "666666667").First(&dev).Error)
	require.NotNil(t, dev.LastSeenAt)

	staleSeen := time.Now().Add(-2 * time.Hour)
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).Model(&model.Device{}).
		Where("id = ?", dev.ID).
		Update("last_seen_at", staleSeen).Error)
	firstSeen := staleSeen

	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).Model(&model.Device{}).
		Where("id = ?", dev.ID).
		Updates(map[string]any{
			"binding_generation": dev.BindingGeneration + 1,
		}).Error)

	w = h.do(t, http.MethodPost, "/api/sysinfo", map[string]any{
		"id": "666666667", "uuid": "stale-sys-uuid",
	}, "")
	require.Equal(t, http.StatusOK, w.Code)

	var after model.Device
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).First(&after, dev.ID).Error)
	require.True(t, firstSeen.Equal(*after.LastSeenAt),
		"a stale-generation sysinfo must not move last_seen: got %v want %v", after.LastSeenAt, firstSeen)
}

// The winning session of the concurrent-claim race carries the device's
// generation, and the losers have no session at all.
//
// Known uncovered branch (SQLite serialises writes, so it cannot be forced):
// claimDeviceTx's RowsAffected==0 re-read — the conditional update losing a
// race between the First and the UPDATE. Its behaviour is pinned only by the
// conditional-update structure and the shared-database CI runs.
func TestLogin_ConcurrentClaim_SessionGenerationMatches(t *testing.T) {
	h := newHarness(t)
	u := h.seedUser(t, "racegen@example.com", "password123", true)
	org := h.seedOrg(t, "acme")
	h.seedMembership(t, u.ID, org.ID)

	token, _ := h.login(t, "racegen@example.com", "password123", "777777777", "racegen-uuid")

	var dev model.Device
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).
		Where("rustdesk_id = ?", "777777777").First(&dev).Error)

	var sess model.CompatSession
	require.NoError(t, h.db.DB.Where("device_id = ?", "777777777").First(&sess).Error)
	require.Equal(t, dev.BindingGeneration, sess.BindingGeneration)
	require.NotEmpty(t, token)
}

// The claim and the session row land in one transaction: a client presenting
// a bound device it does not own gets a 403 and leaves no session row behind.
func TestLogin_ForeignClaimLeavesNoSession(t *testing.T) {
	h := newHarness(t)
	u := h.seedUser(t, "foreign@example.com", "password123", true)
	org := h.seedOrg(t, "acme")
	h.seedMembership(t, u.ID, org.ID)

	// Another client instance claims the device first.
	owner := h.seedUser(t, "owner@example.com", "password123", true)
	h.seedMembership(t, owner.ID, org.ID)
	_, _ = h.login(t, "owner@example.com", "password123", "888888888", "owner-uuid")

	w := h.do(t, http.MethodPost, "/api/login", map[string]string{
		"username": "foreign@example.com", "password": "password123",
		"id": "888888888", "uuid": "foreign-uuid",
	}, "")
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	var count int64
	require.NoError(t, h.db.DB.Model(&model.CompatSession{}).
		Where("user_id = ? AND device_id = ?", u.ID, "888888888").
		Count(&count).Error)
	require.Equal(t, int64(0), count, "a refused claim leaves no session row")

	var dev model.Device
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).
		Where("rustdesk_id = ?", "888888888").First(&dev).Error)
	require.Equal(t, "owner-uuid", dev.BoundUUID, "the binding is untouched")
}
