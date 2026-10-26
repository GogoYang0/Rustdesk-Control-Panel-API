package compatapi_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// seedStrategy creates a strategy row directly: these tests are about the
// delivery contract (what the heartbeat puts on the wire), not about the CRUD
// service, which has its own suite.
func seedStrategy(t *testing.T, h *harness, orgID uint, name, options string, version int64, enabled bool) model.Strategy {
	t.Helper()
	row := model.Strategy{
		OrganizationID:    orgID,
		Name:              name,
		ConfigOptionsJSON: options,
		Version:           version,
		Enabled:           enabled,
	}
	require.NoError(t, h.db.DB.Create(&row).Error)
	return row
}

func assignStrategyToDevice(t *testing.T, h *harness, orgID, deviceID, strategyID uint) {
	t.Helper()
	require.NoError(t, store.ScopedByOrg(h.db.DB, orgID).Model(&model.Device{}).
		Where("id = ?", deviceID).Update("strategy_id", strategyID).Error)
}

// loginHeartbeatDevice onboards one client and returns its device row.
func loginHeartbeatDevice(t *testing.T, h *harness, rustdeskID string) (model.Organization, model.Device) {
	t.Helper()
	email := "hb-" + rustdeskID + "@example.com"
	u := h.seedUser(t, email, "password123", true)
	org := h.seedOrg(t, "hb-org-"+rustdeskID)
	h.seedMembership(t, u.ID, org.ID)
	h.login(t, email, "password123", rustdeskID, "uuid-"+rustdeskID)

	var dev model.Device
	require.NoError(t, store.WithoutTenantScope(h.db.DB).
		Where("rustdesk_id = ? AND organization_id = ?", rustdeskID, org.ID).First(&dev).Error)
	return org, dev
}

func heartbeat(t *testing.T, h *harness, rustdeskID string, modifiedAt int64) map[string]any {
	t.Helper()
	w := h.do(t, http.MethodPost, "/api/heartbeat", map[string]any{
		"id": rustdeskID, "uuid": "uuid-" + rustdeskID, "modified_at": modifiedAt,
	}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	return decodeCompatBody(t, w)
}

// TestHeartbeat_DeliversStrategyAndVersion pins the delivery contract:
// options and `modified_at` travel together, and an echoed version suppresses
// the re-send.
func TestHeartbeat_DeliversStrategyAndVersion(t *testing.T) {
	h := newHarness(t)
	org, dev := loginHeartbeatDevice(t, h, "880001")
	s := seedStrategy(t, h, org.ID, "Baseline", `{"enable-audio":"N"}`, 4, true)
	assignStrategyToDevice(t, h, org.ID, dev.ID, s.ID)

	body := heartbeat(t, h, "880001", 0)
	strategy, ok := body["strategy"].(map[string]any)
	require.True(t, ok, "the first heartbeat must carry the strategy: %v", body)
	options, ok := strategy["config_options"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "N", options["enable-audio"])
	require.EqualValues(t, 4, body["modified_at"])

	// The client echoes the version it stored: nothing is re-sent.
	body = heartbeat(t, h, "880001", 4)
	require.NotContains(t, body, "strategy")
	require.NotContains(t, body, "modified_at",
		"a version without options would tell the client it is up to date while it is not")

	// A new version is delivered again, with the new options.
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).Model(&model.Strategy{}).
		Where("id = ?", s.ID).
		Updates(map[string]any{
			"config_options_json": `{"enable-audio":"Y"}`,
			"version":             5,
		}).Error)
	body = heartbeat(t, h, "880001", 4)
	strategy, ok = body["strategy"].(map[string]any)
	require.True(t, ok)
	options, ok = strategy["config_options"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "Y", options["enable-audio"])
	require.EqualValues(t, 5, body["modified_at"])
}

// TestHeartbeat_NoStrategySendsNothing: without an assignment the response must
// stay empty, in particular it must not carry `modified_at`.
func TestHeartbeat_NoStrategySendsNothing(t *testing.T) {
	h := newHarness(t)
	loginHeartbeatDevice(t, h, "880002")

	body := heartbeat(t, h, "880002", 0)
	require.NotContains(t, body, "strategy")
	require.NotContains(t, body, "modified_at")
}

// TestHeartbeat_DisabledStrategySendsNothing: the kill switch must hold at the
// wire, not only in the management list.
func TestHeartbeat_DisabledStrategySendsNothing(t *testing.T) {
	h := newHarness(t)
	org, dev := loginHeartbeatDevice(t, h, "880003")
	s := seedStrategy(t, h, org.ID, "Off", `{"enable-audio":"N"}`, 2, false)
	assignStrategyToDevice(t, h, org.ID, dev.ID, s.ID)

	body := heartbeat(t, h, "880003", 0)
	require.NotContains(t, body, "strategy")
	require.NotContains(t, body, "modified_at")
}

// TestHeartbeat_StaleSessionSendsNothing: a session whose binding moved on
// (re-bound uuid) must not receive the organization's policy.
func TestHeartbeat_StaleSessionSendsNothing(t *testing.T) {
	h := newHarness(t)
	org, dev := loginHeartbeatDevice(t, h, "880004")
	s := seedStrategy(t, h, org.ID, "Baseline", `{"enable-audio":"N"}`, 1, true)
	assignStrategyToDevice(t, h, org.ID, dev.ID, s.ID)

	// Another client instance claimed the device after this session was issued.
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).Model(&model.Device{}).
		Where("id = ?", dev.ID).Update("bound_uuid", "uuid-other").Error)

	body := heartbeat(t, h, "880004", 0)
	require.NotContains(t, body, "strategy")
}

// TestHeartbeat_GroupAssignedStrategy: the middle layer of the resolution order
// must work end to end, not just in the service.
func TestHeartbeat_GroupAssignedStrategy(t *testing.T) {
	h := newHarness(t)
	org, dev := loginHeartbeatDevice(t, h, "880005")
	grp := model.DeviceGroup{OrganizationID: org.ID, Name: "site"}
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).Create(&grp).Error)

	s := seedStrategy(t, h, org.ID, "Group", `{"enable-clipboard":"N"}`, 7, true)
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).Model(&model.DeviceGroup{}).
		Where("id = ?", grp.ID).Update("strategy_id", s.ID).Error)
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).Model(&model.Device{}).
		Where("id = ?", dev.ID).Update("device_group_id", grp.ID).Error)

	body := heartbeat(t, h, "880005", 0)
	strategy, ok := body["strategy"].(map[string]any)
	require.True(t, ok, "%v", body)
	options, ok := strategy["config_options"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "N", options["enable-clipboard"])
	require.EqualValues(t, 7, body["modified_at"])
}
