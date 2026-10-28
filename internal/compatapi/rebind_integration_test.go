package compatapi_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/compatapi"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/device"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/limit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// rebindHarness drives the compat endpoints against a mutable clock, because
// the heartbeat path coalesces reports inside a 30s window: a fixed clock
// would make "the old session can no longer drive the device" pass for the
// wrong reason.
type rebindHarness struct {
	router *gin.Engine
	db     *store.Store
	devSvc *device.Service
	clock  time.Time
	org    model.Organization
	user   model.User
}

func newRebindHarness(t *testing.T) *rebindHarness {
	t.Helper()
	gin.SetMode(gin.TestMode)

	dsn := "file:rebindtest_" + sanitize(t.Name()) + "?mode=memory&cache=shared"
	st, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	require.NoError(t, st.DB.AutoMigrate(
		&model.User{}, &model.RefreshToken{}, &model.UserTOTP{},
		&model.Organization{}, &model.Membership{}, &model.CompatLoginChallenge{},
		&model.AuditLog{},
		&model.Device{}, &model.DeviceHeartbeat{},
		&model.CompatSession{},
	))

	h := &rebindHarness{
		db:    st,
		clock: time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC),
	}
	h.devSvc = device.NewService(st.DB, audit.NewGormAuditor(st.DB), func() time.Time { return h.clock })

	h.router = gin.New()
	compatapi.Mount(h.router, compatapi.Deps{
		DB:        st.DB,
		Issuer:    auth.NewIssuer("test-secret", time.Minute, time.Hour),
		Devices:   h.devSvc,
		Guard:     limit.NewLoginGuard(),
		Now:       func() time.Time { return h.clock },
		AccessTTL: time.Hour,
	})

	hash, err := auth.HashPassword("password123")
	require.NoError(t, err)
	h.user = model.User{Email: "rebind@example.com", PasswordHash: hash, EmailVerified: true}
	require.NoError(t, st.DB.Create(&h.user).Error)
	h.org = model.Organization{Name: "rebind-org"}
	require.NoError(t, st.DB.Create(&h.org).Error)
	require.NoError(t, st.DB.Create(&model.Membership{
		OrganizationID: h.org.ID, UserID: h.user.ID, RoleID: 1,
	}).Error)
	return h
}

func (h *rebindHarness) advance(d time.Duration) { h.clock = h.clock.Add(d) }

func (h *rebindHarness) do(t *testing.T, method, path string, body any, token string) *httptest.ResponseRecorder {
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

func (h *rebindHarness) login(t *testing.T, id, uuid string) string {
	t.Helper()
	w := h.do(t, http.MethodPost, "/api/login", map[string]string{
		"username": "rebind@example.com", "password": "password123", "id": id, "uuid": uuid,
	}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.AccessToken)
	return resp.AccessToken
}

func (h *rebindHarness) heartbeat(t *testing.T, token, id, uuid string) {
	t.Helper()
	w := h.do(t, http.MethodPost, "/api/heartbeat", map[string]string{"id": id, "uuid": uuid}, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

func (h *rebindHarness) deviceRow(t *testing.T, rustdeskID string) model.Device {
	t.Helper()
	var d model.Device
	require.NoError(t, store.ScopedByOrg(h.db.DB, h.org.ID).
		Where("rustdesk_id = ?", rustdeskID).First(&d).Error)
	return d
}

func TestResetThenOldSessionCannotDrive(t *testing.T) {
	h := newRebindHarness(t)
	const id = "111111111"
	token := h.login(t, id, "old-uuid")

	h.advance(60 * time.Second)
	h.heartbeat(t, token, id, "old-uuid")
	first := h.deviceRow(t, id)
	require.NotNil(t, first.LastSeenAt)

	_, err := h.devSvc.ResetBinding(t.Context(), h.org.ID, first.ID, h.user.ID, "员工换机")
	require.NoError(t, err)

	// A second heartbeat well past the 30s coalescing window must still leave
	// last_seen_at untouched: the generation moved, so the session is stale.
	h.advance(60 * time.Second)
	h.heartbeat(t, token, id, "old-uuid")
	after := h.deviceRow(t, id)
	require.Equal(t, *first.LastSeenAt, *after.LastSeenAt, "the old session must not drive the device")
	require.Equal(t, "", after.BoundUUID)
	require.EqualValues(t, 2, after.BindingGeneration)
}

func TestResetThenNewMachineClaimsAndGenerationJumps(t *testing.T) {
	h := newRebindHarness(t)
	const id = "111111111"
	h.login(t, id, "old-uuid")
	first := h.deviceRow(t, id)
	require.EqualValues(t, 1, first.BindingGeneration)

	_, err := h.devSvc.ResetBinding(t.Context(), h.org.ID, first.ID, h.user.ID, "员工换机")
	require.NoError(t, err)

	newToken := h.login(t, id, "new-uuid")
	claimed := h.deviceRow(t, id)
	require.Equal(t, "new-uuid", claimed.BoundUUID)
	require.EqualValues(t, 3, claimed.BindingGeneration, "first claim + reset + re-claim")

	h.advance(60 * time.Second)
	h.heartbeat(t, newToken, id, "new-uuid")
	after := h.deviceRow(t, id)
	require.NotNil(t, after.LastSeenAt)
	require.True(t, after.Online(h.clock), "the re-claimed session is live again")
}

func TestSharedUUIDCloneIsOnlyEscapableByReset(t *testing.T) {
	h := newRebindHarness(t)
	const id = "111111111"

	// Two machines carrying the same uuid (a cloned image) both pass the
	// binding check: the panel cannot tell them apart — documented non-goal.
	h.login(t, id, "cloned-uuid")
	h.login(t, id, "cloned-uuid")
	dev := h.deviceRow(t, id)
	require.EqualValues(t, 1, dev.BindingGeneration)

	// The reset is the escape hatch: the next login re-claims the device and
	// the generation moves again.
	_, err := h.devSvc.ResetBinding(t.Context(), h.org.ID, dev.ID, h.user.ID, "克隆装机")
	require.NoError(t, err)
	h.login(t, id, "cloned-uuid")
	after := h.deviceRow(t, id)
	require.Equal(t, "cloned-uuid", after.BoundUUID)
	require.EqualValues(t, 3, after.BindingGeneration)
}
