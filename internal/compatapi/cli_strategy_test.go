package compatapi_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// TestCLIAssign_StrategyName pins the reversal of wave 2's D5: the client's
// `--assign strategy_name` now resolves a strategy by name inside the token's
// organization and assigns it to the device.
func TestCLIAssign_StrategyName(t *testing.T) {
	h := newCLIHarness(t)
	dev := h.seedDevice(t, "cli-3001", "")
	token := h.seedToken(t, h.owner.ID, []string{authz.PermDeviceWrite, authz.PermStrategyManage})

	row := model.Strategy{
		OrganizationID:    h.org.ID,
		Name:              "Baseline",
		ConfigOptionsJSON: `{"enable-audio":"N"}`,
		Version:           1,
		Enabled:           true,
	}
	require.NoError(t, h.db.DB.Create(&row).Error)

	// Case-insensitive on purpose: the name is resolved the same way the
	// uniqueness rule compares it.
	w := h.do(t, http.MethodPost, "/api/devices/cli", map[string]any{
		"id": "cli-3001", "strategy_name": "baseline",
	}, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var stored model.Device
	require.NoError(t, store.ScopedByOrg(h.db.DB, h.org.ID).First(&stored, dev.ID).Error)
	require.NotNil(t, stored.StrategyID)
	require.Equal(t, row.ID, *stored.StrategyID)
	require.EqualValues(t, 1, h.auditCount(t, "strategy.assign"))
}

func TestCLIAssign_StrategyNameUnknownIsNotFound(t *testing.T) {
	h := newCLIHarness(t)
	dev := h.seedDevice(t, "cli-3002", "")
	token := h.seedToken(t, h.owner.ID, []string{authz.PermDeviceWrite, authz.PermStrategyManage})

	w := h.do(t, http.MethodPost, "/api/devices/cli", map[string]any{
		"id": "cli-3002", "strategy_name": "missing", "note": "should not apply",
	}, token)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "strategy")

	// A refused name must fail the whole call: no partial device update, no
	// assignment.
	var stored model.Device
	require.NoError(t, store.ScopedByOrg(h.db.DB, h.org.ID).First(&stored, dev.ID).Error)
	require.Nil(t, stored.StrategyID)
	require.Empty(t, stored.Note)
}

func TestCLIAssign_StrategyNameEmptyIsBadRequest(t *testing.T) {
	h := newCLIHarness(t)
	h.seedDevice(t, "cli-3003", "")
	token := h.seedToken(t, h.owner.ID, []string{authz.PermDeviceWrite, authz.PermStrategyManage})

	w := h.do(t, http.MethodPost, "/api/devices/cli", map[string]any{
		"id": "cli-3003", "strategy_name": "",
	}, token)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
}

// TestCLIAssign_StrategyNeedsManagePermission: device.write is delegable and
// strategy.manage is not, so the CLI path must not hand the non-delegable
// capability to a token that only holds the former.
func TestCLIAssign_StrategyNeedsManagePermission(t *testing.T) {
	h := newCLIHarness(t)
	dev := h.seedDevice(t, "cli-3004", "")
	token := h.seedToken(t, h.owner.ID, []string{authz.PermDeviceWrite})

	require.NoError(t, h.db.DB.Create(&model.Strategy{
		OrganizationID: h.org.ID, Name: "Baseline", ConfigOptionsJSON: `{}`,
		Version: 1, Enabled: true,
	}).Error)

	w := h.do(t, http.MethodPost, "/api/devices/cli", map[string]any{
		"id": "cli-3004", "strategy_name": "Baseline",
	}, token)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	var stored model.Device
	require.NoError(t, store.ScopedByOrg(h.db.DB, h.org.ID).First(&stored, dev.ID).Error)
	require.Nil(t, stored.StrategyID)
}
