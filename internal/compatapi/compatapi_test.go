package compatapi_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/compatapi"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/device"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/limit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

type harness struct {
	router *gin.Engine
	db     store.Store
	issuer *auth.Issuer
	guard  *limit.LoginGuard
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	gin.SetMode(gin.TestMode)

	dsn := "file:compattest_" + sanitize(t.Name()) + "?mode=memory&cache=shared"
	st, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	require.NoError(t, st.DB.AutoMigrate(
		&model.User{}, &model.RefreshToken{},
		&model.Organization{}, &model.Membership{}, &model.Invitation{},
		&model.AuditLog{},
		&model.Device{}, &model.DeviceHeartbeat{},
		&model.CompatSession{},
		&model.AddressBook{}, &model.AddressBookPeer{}, &model.AddressBookTag{},
	))

	issuer := auth.NewIssuer("test-secret", time.Minute, time.Hour)
	guard := limit.NewLoginGuard()
	r := gin.New()
	compatapi.Mount(r, compatapi.Deps{
		DB:        st.DB,
		Issuer:    issuer,
		Devices:   device.NewService(st.DB, nil, nil),
		Guard:     guard,
		AccessTTL: time.Hour,
	})
	return &harness{router: r, db: *st, issuer: issuer, guard: guard}
}

func (h *harness) do(t *testing.T, method, path string, body any, token string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&buf).Encode(body))
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.0.2.10:1234"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.router.ServeHTTP(w, req)
	return w
}

func (h *harness) seedUser(t *testing.T, email, password string, verified bool) model.User {
	t.Helper()
	hash, err := auth.HashPassword(password)
	require.NoError(t, err)
	u := model.User{Email: email, PasswordHash: hash, EmailVerified: verified}
	require.NoError(t, h.db.DB.Create(&u).Error)
	return u
}

func (h *harness) seedMembership(t *testing.T, userID, orgID uint) {
	t.Helper()
	require.NoError(t, h.db.DB.Create(&model.Membership{
		OrganizationID: orgID,
		UserID:         userID,
		Role:           model.RoleOwner,
	}).Error)
}

func (h *harness) seedOrg(t *testing.T, name string) model.Organization {
	t.Helper()
	org := model.Organization{Name: name}
	require.NoError(t, h.db.DB.Create(&org).Error)
	return org
}

// loadFixture reads a client protocol fixture from testdata/.
func loadFixture(t *testing.T, name string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	return m
}

// login performs the client flow and returns the access token plus the raw
// response body.
func (h *harness) login(t *testing.T, username, password, deviceID, deviceUUID string) (string, map[string]any) {
	t.Helper()
	w := h.do(t, http.MethodPost, "/api/login", map[string]string{
		"username": username, "password": password,
		"id": deviceID, "uuid": deviceUUID,
	}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	token, _ := resp["access_token"].(string)
	require.NotEmpty(t, token)
	return token, resp
}

// The login response must match the frozen client fixture shape: an
// AuthBody with access_token, type and a user payload carrying name/email.
func TestLogin_Success_IssuesCompatToken(t *testing.T) {
	h := newHarness(t)
	u := h.seedUser(t, "alice@example.com", "password123", true)
	org := h.seedOrg(t, "acme")
	h.seedMembership(t, u.ID, org.ID)

	fixture := loadFixture(t, "login_response.json")

	token, resp := h.login(t, "alice@example.com", "password123", "123456789", "ZmFrZS1kZXZpY2UtdXVpZA")

	// Every fixture key must be present in the response at the top level.
	for k := range fixture {
		require.Contains(t, resp, k)
	}
	require.Equal(t, "access_token", resp["type"])
	user, ok := resp["user"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "alice@example.com", user["name"])
	require.Equal(t, "alice@example.com", user["email"])

	// The token parses as a compat token bound to the organization.
	uid, orgID, jti, err := h.issuer.ParseCompat(token)
	require.NoError(t, err)
	require.Equal(t, u.ID, uid)
	require.Equal(t, org.ID, orgID)
	require.NotEmpty(t, jti)

	// The session row exists and matches the token.
	var session model.CompatSession
	require.NoError(t, h.db.DB.Where("jti = ?", jti).First(&session).Error)
	require.Equal(t, org.ID, session.OrganizationID)
	require.Equal(t, "123456789", session.DeviceID)
	require.Equal(t, "ZmFrZS1kZXZpY2UtdXVpZA", session.UUID)
}

// C16: a multi-org account without a selector must be rejected with
// guidance, and email#orgID must bind the named organization.
func TestLogin_MultiOrg_RequiresDisambiguation(t *testing.T) {
	h := newHarness(t)
	u := h.seedUser(t, "multi@example.com", "password123", true)
	orgA := h.seedOrg(t, "org-a")
	orgB := h.seedOrg(t, "org-b")
	h.seedMembership(t, u.ID, orgA.ID)
	h.seedMembership(t, u.ID, orgB.ID)

	w := h.do(t, http.MethodPost, "/api/login", map[string]string{
		"username": "multi@example.com", "password": "password123",
	}, "")
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "email#orgID")

	token, _ := h.login(t, "multi@example.com#"+uintString(orgB.ID), "password123", "", "")
	_, orgID, _, err := h.issuer.ParseCompat(token)
	require.NoError(t, err)
	require.Equal(t, orgB.ID, orgID, "the selector must bind the named organization")
}

// Issue #17 gates every login path: an unverified mailbox cannot log in
// through the compat layer either.
func TestLogin_RejectsUnverified(t *testing.T) {
	h := newHarness(t)
	u := h.seedUser(t, "unv@example.com", "password123", false)
	org := h.seedOrg(t, "acme")
	h.seedMembership(t, u.ID, org.ID)

	w := h.do(t, http.MethodPost, "/api/login", map[string]string{
		"username": "unv@example.com", "password": "password123",
	}, "")
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "not verified")
}

// Review Focus #4: the sixth attempt from one IP is throttled.
func TestLogin_RateLimited(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "rl@example.com", "password123", true)

	for i := 0; i < 5; i++ {
		w := h.do(t, http.MethodPost, "/api/login", map[string]string{
			"username": "rl@example.com", "password": "wrong-pass-1",
		}, "")
		require.NotEqual(t, http.StatusTooManyRequests, w.Code, "attempt %d", i+1)
	}
	w := h.do(t, http.MethodPost, "/api/login", map[string]string{
		"username": "rl@example.com", "password": "wrong-pass-1",
	}, "")
	require.Equal(t, http.StatusTooManyRequests, w.Code)
}

// Rotating the "#orgID" suffix or the letter case must not bypass the
// per-account lockout: every username variant feeds the same normalized
// lock key, so failureLimit failures under any spelling lock the account
// (CWE-307).
func TestLogin_LockKeyNormalizesUsername(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "victim@example.com", "password123", true)

	variants := []string{
		"Victim@example.com#1",
		"victim@example.com#2",
		"VICTIM@example.com#3",
		"victim@example.com#4",
		" victim@example.com#5",
	}
	for i, v := range variants {
		w := h.do(t, http.MethodPost, "/api/login", map[string]string{
			"username": v, "password": "wrong-pass-1",
		}, "")
		require.NotEqual(t, http.StatusInternalServerError, w.Code)
		require.Equal(t, http.StatusUnauthorized, w.Code, "variant %d: %s", i+1, v)
	}

	// All five failures share one normalized key: the pair is locked.
	require.True(t, h.guard.Locked("victim@example.com", "192.0.2.10"),
		"rotating suffixes or case must not split the failure counter")
	// A differently-cased spelling is the same key for the handler too.
	w := h.do(t, http.MethodPost, "/api/login", map[string]string{
		"username": "Victim@Example.com", "password": "password123",
	}, "")
	require.Equal(t, http.StatusTooManyRequests, w.Code, w.Body.String())
}

// The session endpoints require a bearer compat token; management tokens
// are a different family and must be rejected.
func TestCurrentUser_BearerOnly(t *testing.T) {
	h := newHarness(t)
	u := h.seedUser(t, "cur@example.com", "password123", true)
	org := h.seedOrg(t, "acme")
	h.seedMembership(t, u.ID, org.ID)

	// No token at all.
	w := h.do(t, http.MethodPost, "/api/currentUser", nil, "")
	require.Equal(t, http.StatusUnauthorized, w.Code)

	token, _ := h.login(t, "cur@example.com", "password123", "", "")
	w = h.do(t, http.MethodPost, "/api/currentUser", nil, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var user map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &user))
	require.Equal(t, "cur@example.com", user["name"])

	// A management-family token must not open compat endpoints.
	adminIssuer := auth.NewIssuer("test-secret", time.Minute, time.Hour)
	adminToken, _, err := adminIssuer.Issue(u.ID)
	require.NoError(t, err)
	w = h.do(t, http.MethodPost, "/api/currentUser", nil, adminToken)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

// The client's fire-and-forget heartbeat must refresh the device's
// last-seen timestamp and record a heartbeat event (issue C11).
func TestHeartbeat_UpdatesDeviceLastSeen(t *testing.T) {
	h := newHarness(t)
	u := h.seedUser(t, "hb@example.com", "password123", true)
	org := h.seedOrg(t, "acme")
	h.seedMembership(t, u.ID, org.ID)

	fixture := loadFixture(t, "heartbeat_request.json")
	h.login(t, "hb@example.com", "password123",
		fixture["id"].(string), fixture["uuid"].(string))

	w := h.do(t, http.MethodPost, "/api/heartbeat", fixture, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var dev model.Device
	// Raw DB reads on tenant tables fail closed; scope to the org.
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).
		Where("rustdesk_id = ?", fixture["id"]).First(&dev).Error)
	require.NotNil(t, dev.LastSeenAt, "the heartbeat must update last_seen_at")
	require.Equal(t, org.ID, dev.OrganizationID)

	var beats int64
	// DeviceHeartbeat also carries a tenant plugin; scope the count.
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).
		Model(&model.DeviceHeartbeat{}).
		Where("device_id = ?", dev.ID).Count(&beats).Error)
	require.EqualValues(t, 1, beats)

	// A heartbeat from an unknown device binding is silently accepted.
	w = h.do(t, http.MethodPost, "/api/heartbeat",
		map[string]any{"id": "999999999", "uuid": "unknown-uuid"}, "")
	require.Equal(t, http.StatusOK, w.Code)
}

// A forged rustdesk id must not register devices or heartbeats in the
// session's organization: the uuid is a stable hardware identifier, not a
// secret, so the request id has to match the device bound at login
// (CWE-639). The endpoint stays fire-and-forget (200) for the client.
func TestHeartbeat_ForgedDeviceID_IsIgnored(t *testing.T) {
	h := newHarness(t)
	u := h.seedUser(t, "forge@example.com", "password123", true)
	org := h.seedOrg(t, "acme")
	h.seedMembership(t, u.ID, org.ID)

	fixture := loadFixture(t, "heartbeat_request.json")
	h.login(t, "forge@example.com", "password123",
		fixture["id"].(string), fixture["uuid"].(string))

	// Same uuid as the live session, but a device id that session never
	// bound: both heartbeat and sysinfo must ignore it.
	forged := map[string]any{"id": "000000001", "uuid": fixture["uuid"]}
	w := h.do(t, http.MethodPost, "/api/heartbeat", forged, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.do(t, http.MethodPost, "/api/sysinfo",
		map[string]any{"id": "000000001", "uuid": fixture["uuid"], "os": "Windows"}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// Only the device bound at login exists; no heartbeat was written.
	var devices []model.Device
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).Find(&devices).Error)
	require.Len(t, devices, 1)
	require.Equal(t, fixture["id"], devices[0].RustdeskID,
		"a forged id must not register an extra device")

	var beats int64
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).
		Model(&model.DeviceHeartbeat{}).Count(&beats).Error)
	require.Zero(t, beats, "a forged id must not write a heartbeat")
}

// Review Focus #1: a session bound to org A must never see org B devices.
func TestPeers_CrossOrgEmpty(t *testing.T) {
	h := newHarness(t)
	u := h.seedUser(t, "peer@example.com", "password123", true)
	orgA := h.seedOrg(t, "org-a")
	orgB := h.seedOrg(t, "org-b")
	h.seedMembership(t, u.ID, orgA.ID)

	// A device lives in org B; the session is bound to org A.
	require.NoError(t, h.db.DB.Create(&model.Device{
		OrganizationID: orgB.ID,
		RustdeskID:     "777777777",
		Name:           "b-pc",
	}).Error)

	token, _ := h.login(t, "peer@example.com", "password123", "", "")
	w := h.do(t, http.MethodGet, "/api/peers", nil, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var resp struct {
		Peers []map[string]any `json:"peers"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Empty(t, resp.Peers, "devices of another organization must not leak")

	// A device in the bound organization shows up.
	require.NoError(t, h.db.DB.Create(&model.Device{
		OrganizationID: orgA.ID,
		RustdeskID:     "123456789",
		Name:           "a-pc",
	}).Error)
	w = h.do(t, http.MethodGet, "/api/peers", nil, token)
	require.Equal(t, http.StatusOK, w.Code)
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Len(t, resp.Peers, 1)
	require.Equal(t, "123456789", resp.Peers[0]["id"])

	fixture := loadFixture(t, "peers_response.json")
	for k := range fixture["peers"].([]any)[0].(map[string]any) {
		require.Contains(t, resp.Peers[0], k)
	}
}

// The client's logout revokes the session server-side; the token must stop
// working immediately afterwards.
func TestLogout_RevokesSession(t *testing.T) {
	h := newHarness(t)
	u := h.seedUser(t, "lo@example.com", "password123", true)
	org := h.seedOrg(t, "acme")
	h.seedMembership(t, u.ID, org.ID)

	token, _ := h.login(t, "lo@example.com", "password123", "", "")

	w := h.do(t, http.MethodPost, "/api/logout", nil, token)
	require.Equal(t, http.StatusOK, w.Code)

	w = h.do(t, http.MethodPost, "/api/currentUser", nil, token)
	require.Equal(t, http.StatusUnauthorized, w.Code, "a revoked session must stop working")
}

// login-options is the client's capability probe and answers an empty list.
func TestLoginOptions_EmptyList(t *testing.T) {
	h := newHarness(t)
	w := h.do(t, http.MethodGet, "/api/login-options", nil, "")
	require.Equal(t, http.StatusOK, w.Code)
	require.JSONEq(t, "[]", w.Body.String())
}

func uintString(v uint) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func sanitize(name string) string {
	r := map[byte]string{'/': "_", ' ': "_", '-': "_"}
	out := make([]byte, 0, len(name))
	for i := 0; i < len(name); i++ {
		if rep, ok := r[name[i]]; ok {
			out = append(out, rep...)
		} else {
			out = append(out, name[i])
		}
	}
	return string(out)
}

// A member must not take over a device binding another client instance
// already claimed: the first uuid to present a rustdesk id owns it, and a
// foreign-uuid login is refused before any session is issued (CWE-863).
func TestLogin_RejectsForeignDeviceBinding(t *testing.T) {
	h := newHarness(t)
	org := h.seedOrg(t, "acme")
	// The victim device: registered (e.g. by its real client or the admin)
	// and bound to a client instance uuid.
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).Create(&model.Device{
		OrganizationID: org.ID,
		RustdeskID:     "111111111",
		Name:           "office-pc",
		BoundUUID:      "victim-device-uuid",
	}).Error)

	u := h.seedUser(t, "member@example.com", "password123", true)
	h.seedMembership(t, u.ID, org.ID)

	w := h.do(t, http.MethodPost, "/api/login", map[string]string{
		"username": "member@example.com", "password": "password123",
		"id": "111111111", "uuid": "attacker-uuid",
	}, "")
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "already bound")

	// The binding is untouched and no session exists for the attacker.
	var dev model.Device
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).
		Where("rustdesk_id = ?", "111111111").First(&dev).Error)
	require.Equal(t, "victim-device-uuid", dev.BoundUUID)

	var sessions int64
	require.NoError(t, store.WithoutTenantScope(h.db.DB).
		Model(&model.CompatSession{}).Count(&sessions).Error)
	require.Zero(t, sessions, "a refused login must not leave a session")
}

// A device row that exists without a bound uuid (admin-registered or legacy)
// is claimed by the first client login that presents it.
func TestLogin_ClaimsUnboundDevice(t *testing.T) {
	h := newHarness(t)
	org := h.seedOrg(t, "acme")
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).Create(&model.Device{
		OrganizationID: org.ID,
		RustdeskID:     "222222222",
		Name:           "unclaimed",
	}).Error)

	u := h.seedUser(t, "claim@example.com", "password123", true)
	h.seedMembership(t, u.ID, org.ID)

	_, _ = h.login(t, "claim@example.com", "password123", "222222222", "real-uuid")

	var dev model.Device
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).
		Where("rustdesk_id = ?", "222222222").First(&dev).Error)
	require.Equal(t, "real-uuid", dev.BoundUUID, "the first login claims the device")
}

// The legitimate client can re-login with the same uuid: the binding is
// idempotent for the owning instance.
func TestLogin_AllowsSameUUIDRelogin(t *testing.T) {
	h := newHarness(t)
	u := h.seedUser(t, "owner@example.com", "password123", true)
	org := h.seedOrg(t, "acme")
	h.seedMembership(t, u.ID, org.ID)

	h.login(t, "owner@example.com", "password123", "333333333", "same-uuid")
	h.login(t, "owner@example.com", "password123", "333333333", "same-uuid")

	var dev model.Device
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).
		Where("rustdesk_id = ?", "333333333").First(&dev).Error)
	require.Equal(t, "same-uuid", dev.BoundUUID)
}

// A device row removed out of band is treated like a reset: the old session
// must not resurrect the row through a heartbeat, and a stale session must not
// drive a row that was meanwhile re-bound to another client instance.
func TestHeartbeat_DoesNotResurrectOrHijack(t *testing.T) {
	h := newHarness(t)
	u := h.seedUser(t, "stale@example.com", "password123", true)
	org := h.seedOrg(t, "acme")
	h.seedMembership(t, u.ID, org.ID)

	fixture := loadFixture(t, "heartbeat_request.json")
	id := fixture["id"].(string)
	h.login(t, "stale@example.com", "password123", id, fixture["uuid"].(string))

	// The binding moves to another client instance (as a fresh login of the
	// new owner would): the stale session is ignored.
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).Model(&model.Device{}).
		Where("rustdesk_id = ?", id).Update("bound_uuid", "new-owner-uuid").Error)
	w := h.do(t, http.MethodPost, "/api/heartbeat", fixture, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var dev model.Device
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).
		Where("rustdesk_id = ?", id).First(&dev).Error)
	require.Nil(t, dev.LastSeenAt, "a stale session must not drive a re-bound device")

	// The row is removed out of band (the supported reset is the rebind
	// endpoint): the old session must not resurrect it.
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).
		Where("rustdesk_id = ?", id).Delete(&model.Device{}).Error)
	w = h.do(t, http.MethodPost, "/api/heartbeat", fixture, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var count int64
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).
		Model(&model.Device{}).Where("rustdesk_id = ?", id).Count(&count).Error)
	require.Zero(t, count, "the old session must not resurrect the deleted row")
}

// After a device row is removed out of band, the legitimate client re-claims
// it through a fresh login (the supported flow is the rebind endpoint).
func TestLogin_ReclaimsAfterAdminDelete(t *testing.T) {
	h := newHarness(t)
	u := h.seedUser(t, "reclaim@example.com", "password123", true)
	org := h.seedOrg(t, "acme")
	h.seedMembership(t, u.ID, org.ID)

	h.login(t, "reclaim@example.com", "password123", "555555555", "owner-uuid")
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).
		Where("rustdesk_id = ?", "555555555").Delete(&model.Device{}).Error)

	// A fresh login recreates and re-claims the row.
	h.login(t, "reclaim@example.com", "password123", "555555555", "owner-uuid")

	var dev model.Device
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).
		Where("rustdesk_id = ?", "555555555").First(&dev).Error)
	require.Equal(t, "owner-uuid", dev.BoundUUID)
}

// Concurrent first claims of one rustdesk id with different uuids must let
// exactly one login through: the stored binding belongs to a single client
// instance, and every loser is refused before a session is issued. The
// losing requests may surface 403 (bound), 429 (rate limit) or 500
// (SQLite busy) — backend-agnostic invariant, as in PR#23/#24.
func TestLogin_ConcurrentClaim_ExactlyOneWinner(t *testing.T) {
	h := newHarness(t)
	u := h.seedUser(t, "race@example.com", "password123", true)
	org := h.seedOrg(t, "acme")
	h.seedMembership(t, u.ID, org.ID)

	const contenders = 4
	type result struct {
		uuid string
		code int
	}
	results := make(chan result, contenders)
	start := make(chan struct{})
	for i := 0; i < contenders; i++ {
		go func(i int) {
			uuid := fmt.Sprintf("race-uuid-%d", i)
			<-start
			w := h.do(t, http.MethodPost, "/api/login", map[string]string{
				"username": "race@example.com", "password": "password123",
				"id": "666666666", "uuid": uuid,
			}, "")
			results <- result{uuid: uuid, code: w.Code}
		}(i)
	}
	close(start)

	winner := ""
	outcomes := make([]result, 0, contenders)
	for i := 0; i < contenders; i++ {
		r := <-results
		outcomes = append(outcomes, r)
		switch r.code {
		case http.StatusOK:
			require.Empty(t, winner, "two concurrent claims cannot both win")
			winner = r.uuid
		default:
			require.Contains(t, []int{http.StatusForbidden, http.StatusTooManyRequests, http.StatusInternalServerError}, r.code,
				"loser %s got unexpected status %d", r.uuid, r.code)
		}
	}
	require.NotEmpty(t, winner, "one of the contenders must claim the device")

	var dev model.Device
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).
		Where("rustdesk_id = ?", "666666666").First(&dev).Error)
	require.Equal(t, winner, dev.BoundUUID,
		"the stored binding must belong to the winning login")

	// No losing login may leave a session row behind.
	for _, r := range outcomes {
		if r.code == http.StatusOK {
			continue
		}
		var sessions int64
		require.NoError(t, h.db.DB.Model(&model.CompatSession{}).
			Where("user_id = ? AND device_id = ? AND uuid = ?", u.ID, "666666666", r.uuid).
			Count(&sessions).Error)
		require.Zero(t, sessions, "losing login %s must not create a session", r.uuid)
	}

	// The winner's session snapshots the device's binding generation.
	var winnerSession model.CompatSession
	require.NoError(t, h.db.DB.Where("device_id = ? AND uuid = ?", "666666666", winner).
		First(&winnerSession).Error)
	require.Equal(t, dev.BindingGeneration, winnerSession.BindingGeneration)
}

// The uuid is not a secret and is not verified at login, so two client
// instances can present the same one. If the session lookup filters by uuid
// alone, the newest session shadows the older one and the older device's
// heartbeat is silently dropped: any account can take a known device offline by
// logging in with its uuid and a different device id.
func TestHeartbeat_SharedUUID_DoesNotSuppressOtherDevice(t *testing.T) {
	h := newHarness(t)
	org := h.seedOrg(t, "acme")

	victim := h.seedUser(t, "victim@example.com", "password123", true)
	h.seedMembership(t, victim.ID, org.ID)
	attacker := h.seedUser(t, "attacker@example.com", "password123", true)
	h.seedMembership(t, attacker.ID, org.ID)

	const sharedUUID = "shared-hardware-uuid"

	// The victim logs in first and owns its device binding.
	h.login(t, "victim@example.com", "password123", "111111111", sharedUUID)
	// The attacker logs in with its own device id but the victim's uuid: this
	// session is the newest row for that uuid.
	h.login(t, "attacker@example.com", "password123", "222222222", sharedUUID)

	w := h.do(t, http.MethodPost, "/api/heartbeat", map[string]any{
		"id": "111111111", "uuid": sharedUUID,
	}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var dev model.Device
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).
		Where("rustdesk_id = ?", "111111111").First(&dev).Error)
	require.NotNil(t, dev.LastSeenAt,
		"the victim's heartbeat must not be suppressed by another session sharing the uuid")
}

// claimDevice stores the uuid in Device.BoundUUID (size 255) before the session
// row is created (CompatSession.UUID, size 128). On MySQL/PostgreSQL a uuid
// longer than 128 therefore binds the device and then fails to create the
// session: the client gets a 500 and the device stays bound to a value it can
// never present again, so only a binding reset (rebind endpoint) or an
// out-of-band row delete can recover it.
func TestLogin_RejectsOversizedDeviceIdentity(t *testing.T) {
	h := newHarness(t)
	u := h.seedUser(t, "long@example.com", "password123", true)
	org := h.seedOrg(t, "acme")
	h.seedMembership(t, u.ID, org.ID)

	w := h.do(t, http.MethodPost, "/api/login", map[string]string{
		"username": "long@example.com", "password": "password123",
		"id": "111111111", "uuid": strings.Repeat("u", 129),
	}, "")
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	var dev model.Device
	err := store.ScopedByOrg(h.db.DB, org.ID).
		Where("rustdesk_id = ?", "111111111").First(&dev).Error
	require.ErrorIs(t, err, gorm.ErrRecordNotFound,
		"an oversized identity must be rejected before the device is claimed")
}
