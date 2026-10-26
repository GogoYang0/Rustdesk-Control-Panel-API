package compatapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/compatapi"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/device"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/limit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// cliHarness drives POST /api/devices/cli (the RustDesk client's `--assign`
// call) and the login auto-assignment against one organization. The device
// service is wired with the transactional auditor the production entrypoint
// uses: the CLI writes through the same audited service as the management API,
// so without a recorder every mutation is refused.
type cliHarness struct {
	router *gin.Engine
	db     *store.Store
	org    model.Organization
	owner  model.User
}

func newCLIHarness(t *testing.T) *cliHarness {
	t.Helper()
	gin.SetMode(gin.TestMode)

	dsn := "file:clitest_" + sanitize(t.Name()) + "?mode=memory&cache=shared"
	st, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	require.NoError(t, st.DB.AutoMigrate(
		&model.User{}, &model.Organization{}, &model.Membership{}, &model.Role{},
		&model.AuditLog{}, &model.APIToken{},
		&model.Device{}, &model.DeviceHeartbeat{}, &model.CompatSession{},
		&model.UserGroup{}, &model.UserGroupMember{}, &model.DeviceGroup{}, &model.AccessRule{},
	))

	h := &cliHarness{db: st}
	h.router = gin.New()
	compatapi.Mount(h.router, compatapi.Deps{
		DB:        st.DB,
		Issuer:    auth.NewIssuer("test-secret", time.Minute, time.Hour),
		Devices:   device.NewService(st.DB, audit.NewGormAuditor(st.DB), nil),
		Guard:     limit.NewLoginGuard(),
		AccessTTL: time.Hour,
	})

	h.owner = seedCLIUser(t, st, "cli-owner@example.com")
	h.org = model.Organization{Name: "cli-org"}
	require.NoError(t, st.DB.Create(&h.org).Error)
	seedCLIMember(t, st, h.org.ID, h.owner.ID, model.RoleKindOwner)
	return h
}

func seedCLIUser(t *testing.T, st *store.Store, email string) model.User {
	t.Helper()
	hash, err := auth.HashPassword("password123")
	require.NoError(t, err)
	user := model.User{Email: email, PasswordHash: hash, EmailVerified: true}
	require.NoError(t, st.DB.Create(&user).Error)
	return user
}

func seedCLIMember(t *testing.T, st *store.Store, orgID, userID uint, kind string) model.Membership {
	t.Helper()
	require.NoError(t, authz.NewRoleService(st.DB).EnsureBuiltins(orgID))
	role, err := authz.RoleByKindTx(st.DB, orgID, kind)
	require.NoError(t, err)
	membership := model.Membership{OrganizationID: orgID, UserID: userID, RoleID: role.ID}
	require.NoError(t, st.DB.Create(&membership).Error)
	return membership
}

func (h *cliHarness) do(t *testing.T, method, path string, body any, token string) *httptest.ResponseRecorder {
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

func (h *cliHarness) seedDevice(t *testing.T, rustdeskID, uuid string) model.Device {
	t.Helper()
	row := model.Device{
		OrganizationID: h.org.ID,
		RustdeskID:     rustdeskID,
		Name:           rustdeskID,
		BoundUUID:      uuid,
	}
	// Same rule the production registration applies: a bound row starts at
	// generation 1, an unbound row at 0.
	if uuid != "" {
		row.BindingGeneration = 1
	}
	require.NoError(t, h.db.DB.Create(&row).Error)
	return row
}

func (h *cliHarness) seedDeviceGroup(t *testing.T, name string) model.DeviceGroup {
	t.Helper()
	group := model.DeviceGroup{OrganizationID: h.org.ID, Name: name}
	require.NoError(t, h.db.DB.Create(&group).Error)
	return group
}

// seedToken mints a personal token for one user of the harness organization.
func (h *cliHarness) seedToken(t *testing.T, userID uint, permissions []string) string {
	t.Helper()
	plain, _, err := auth.NewTokenService(h.db.DB, nil).
		Create(context.Background(), userID, h.org.ID, "cli", permissions, time.Hour)
	require.NoError(t, err)
	return plain
}

func (h *cliHarness) auditCount(t *testing.T, action string) int64 {
	t.Helper()
	var n int64
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.AuditLog{}).
		Where("organization_id = ? AND action = ?", h.org.ID, action).Count(&n).Error)
	return n
}

func (h *cliHarness) loadDevice(t *testing.T, id uint) model.Device {
	t.Helper()
	var dev model.Device
	require.NoError(t, store.ScopedByOrg(h.db.DB, h.org.ID).First(&dev, id).Error)
	return dev
}

func (h *cliHarness) login(t *testing.T, email, deviceID, uuid string) *httptest.ResponseRecorder {
	t.Helper()
	return h.do(t, http.MethodPost, "/api/login", map[string]string{
		"username": email, "password": "password123", "id": deviceID, "uuid": uuid,
	}, "")
}

// TestCLIAssign_AssignsOwnerGroupNameAndNote pins the whole `--assign` payload
// in one request: owner, device group, name and note change together, each one
// audited, and the client binding is never touched (the login path owns it).
func TestCLIAssign_AssignsOwnerGroupNameAndNote(t *testing.T) {
	h := newCLIHarness(t)
	member := seedCLIUser(t, h.db, "cli-member@example.com")
	seedCLIMember(t, h.db, h.org.ID, member.ID, model.RoleKindMember)
	dev := h.seedDevice(t, "cli-1001", "")
	group := h.seedDeviceGroup(t, "workstations")
	token := h.seedToken(t, h.owner.ID, []string{authz.PermDeviceWrite})

	w := h.do(t, http.MethodPost, "/api/devices/cli", map[string]any{
		"id":                "cli-1001",
		"uuid":              "cli-uuid-1001",
		"user_name":         "cli-member@example.com",
		"device_group_name": "Workstations",
		"device_name":       "front desk",
		"note":              "assigned by the client",
	}, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.JSONEq(t, `{"code":"ok"}`, w.Body.String())

	stored := h.loadDevice(t, dev.ID)
	require.NotNil(t, stored.OwnerUserID)
	require.EqualValues(t, member.ID, *stored.OwnerUserID)
	require.NotNil(t, stored.DeviceGroupID)
	require.EqualValues(t, group.ID, *stored.DeviceGroupID, "the group resolves by name, case-insensitively")
	require.Equal(t, "front desk", stored.Name)
	require.Equal(t, "assigned by the client", stored.Note)

	// One audit row per changed field: the CLI is not a way around the trail.
	for _, action := range []string{"device.assign", "device.rename", "device.group", "device.note"} {
		require.EqualValues(t, 1, h.auditCount(t, action), "audit %s", action)
	}

	// The binding belongs to the login path: `--assign` never rewrites it.
	require.Empty(t, stored.BoundUUID)
	require.Zero(t, stored.BindingGeneration)
}

func TestCLIAssign_RejectsUnsupportedFields(t *testing.T) {
	h := newCLIHarness(t)
	dev := h.seedDevice(t, "cli-2001", "")
	token := h.seedToken(t, h.owner.ID, []string{authz.PermDeviceWrite})

	// A field this deployment does not implement must be refused with its name
	// instead of being ignored: the client would otherwise believe the
	// assignment succeeded (D5).
	w := h.do(t, http.MethodPost, "/api/devices/cli", map[string]any{
		"id": "cli-2001", "strategy_name": "default",
	}, token)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "strategy_name")

	w = h.do(t, http.MethodPost, "/api/devices/cli", map[string]any{
		"id": "cli-2001", "address_book_name": "team",
	}, token)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "address_book_name")

	w = h.do(t, http.MethodPost, "/api/devices/cli", map[string]any{
		"id": "cli-2001", "telemetry": "on",
	}, token)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "telemetry")

	// A request without the device id cannot assign anything.
	w = h.do(t, http.MethodPost, "/api/devices/cli", map[string]any{
		"note": "orphan",
	}, token)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	stored := h.loadDevice(t, dev.ID)
	require.Nil(t, stored.OwnerUserID)
	require.Empty(t, stored.Note)
	for _, action := range []string{"device.assign", "device.rename", "device.group", "device.note"} {
		require.Zero(t, h.auditCount(t, action), "a rejected request writes no %s", action)
	}
}

func TestCLIAssign_CrossOrgTokenIsNotFound(t *testing.T) {
	h := newCLIHarness(t)
	otherOrg := model.Organization{Name: "cli-other-org"}
	require.NoError(t, h.db.DB.Create(&otherOrg).Error)
	foreign := model.Device{OrganizationID: otherOrg.ID, RustdeskID: "cli-shared-3001", Name: "foreign"}
	require.NoError(t, h.db.DB.Create(&foreign).Error)
	token := h.seedToken(t, h.owner.ID, []string{authz.PermDeviceWrite})

	w := h.do(t, http.MethodPost, "/api/devices/cli", map[string]any{
		"id": "cli-shared-3001", "device_name": "stolen", "note": "stolen",
	}, token)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())

	var stored model.Device
	require.NoError(t, store.ScopedByOrg(h.db.DB, otherOrg.ID).First(&stored, foreign.ID).Error)
	require.Equal(t, "foreign", stored.Name)
	require.Empty(t, stored.Note)
	require.Zero(t, h.auditCount(t, "device.rename"))
}

func TestCLIAssign_RequiresDeviceWrite(t *testing.T) {
	h := newCLIHarness(t)
	member := seedCLIUser(t, h.db, "cli-plain@example.com")
	seedCLIMember(t, h.db, h.org.ID, member.ID, model.RoleKindMember)
	dev := h.seedDevice(t, "cli-4001", "")

	// A token can never exceed its owner's live role: even a token that asks
	// for device.write is limited by the member role's set.
	token := h.seedToken(t, member.ID, []string{authz.PermDeviceWrite})
	w := h.do(t, http.MethodPost, "/api/devices/cli", map[string]any{
		"id": "cli-4001", "note": "nope",
	}, token)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// The owner's token without device.write is refused as well.
	readOnly := h.seedToken(t, h.owner.ID, []string{authz.PermDeviceRead})
	w = h.do(t, http.MethodPost, "/api/devices/cli", map[string]any{
		"id": "cli-4001", "note": "nope",
	}, readOnly)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	stored := h.loadDevice(t, dev.ID)
	require.Empty(t, stored.Note)
}

func TestCLIAssign_UnauthorizedWithoutValidToken(t *testing.T) {
	h := newCLIHarness(t)
	h.seedDevice(t, "cli-5001", "")

	w := h.do(t, http.MethodPost, "/api/devices/cli", map[string]any{"id": "cli-5001"}, "")
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())

	w = h.do(t, http.MethodPost, "/api/devices/cli", map[string]any{"id": "cli-5001"}, "not-a-token")
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())

	// A revoked token stays refused.
	token := h.seedToken(t, h.owner.ID, []string{authz.PermDeviceWrite})
	svc := auth.NewTokenService(h.db.DB, nil)
	tokens, err := svc.List(context.Background(), h.owner.ID, h.org.ID)
	require.NoError(t, err)
	require.Len(t, tokens, 1)
	require.NoError(t, svc.Revoke(context.Background(), h.owner.ID, tokens[0].ID))

	w = h.do(t, http.MethodPost, "/api/devices/cli", map[string]any{"id": "cli-5001"}, token)
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
}

func TestCLIAssign_UnknownOwnerOrGroupIsNotFound(t *testing.T) {
	h := newCLIHarness(t)
	dev := h.seedDevice(t, "cli-6001", "")
	token := h.seedToken(t, h.owner.ID, []string{authz.PermDeviceWrite})
	_ = dev

	// An outsider (no membership here) can never own a device of this tenant.
	stranger := seedCLIUser(t, h.db, "cli-stranger@example.com")
	w := h.do(t, http.MethodPost, "/api/devices/cli", map[string]any{
		"id": "cli-6001", "user_name": stranger.Email,
	}, token)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())

	w = h.do(t, http.MethodPost, "/api/devices/cli", map[string]any{
		"id": "cli-6001", "device_group_name": "no-such-group",
	}, token)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())

	stored := h.loadDevice(t, dev.ID)
	require.Nil(t, stored.OwnerUserID)
	require.Nil(t, stored.DeviceGroupID)
}

func TestLogin_AutoAssignsUnclaimedDevice(t *testing.T) {
	h := newCLIHarness(t)
	dev := h.seedDevice(t, "cli-7001", "")

	w := h.login(t, "cli-owner@example.com", "cli-7001", "cli-uuid-7001")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	stored := h.loadDevice(t, dev.ID)
	require.NotNil(t, stored.OwnerUserID, "a login claims an unowned device")
	require.EqualValues(t, h.owner.ID, *stored.OwnerUserID)
}

func TestLogin_DoesNotStealExistingOwner(t *testing.T) {
	h := newCLIHarness(t)
	other := seedCLIUser(t, h.db, "cli-other@example.com")
	seedCLIMember(t, h.db, h.org.ID, other.ID, model.RoleKindMember)
	dev := h.seedDevice(t, "cli-8001", "")
	require.NoError(t, store.ScopedByOrg(h.db.DB, h.org.ID).Model(&model.Device{}).
		Where("id = ?", dev.ID).Update("owner_user_id", other.ID).Error)

	w := h.login(t, "cli-owner@example.com", "cli-8001", "cli-uuid-8001")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	stored := h.loadDevice(t, dev.ID)
	require.NotNil(t, stored.OwnerUserID)
	require.EqualValues(t, other.ID, *stored.OwnerUserID, "login must not reassign an owned device")
}
