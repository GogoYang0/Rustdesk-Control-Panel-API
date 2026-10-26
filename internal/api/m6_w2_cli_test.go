package api_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// TestCLIAssign_ProducesExactlyTheDomainAuditRows pins the interaction between
// the compat CLI endpoint and the management audit middleware: the domain
// entries commit inside the service transaction, so the request must not add a
// generic HTTP fallback row on top. It also pins that /api/devices/cli is a
// compat route reachable with a personal token while the management JWT
// middleware never covers /api/* paths.
func TestCLIAssign_ProducesExactlyTheDomainAuditRows(t *testing.T) {
	h, orgID, owner, _, member, _, _, _ := m4Org(t)
	dev := createDevice(t, h, orgID, seedsAdminToken(t, h, orgID, owner.ID, authz.PermDeviceWrite), "cli laptop", "w2-cli-9001")

	w := h.do(t, http.MethodPost, "/api/devices/cli", map[string]any{
		"id": "w2-cli-9001", "user_name": "m4-member@example.com", "note": "via cli",
	}, seedsAdminToken(t, h, orgID, owner.ID, authz.PermDeviceWrite))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.JSONEq(t, `{"code":"ok"}`, w.Body.String())

	require.EqualValues(t, 1, countAudit(t, h, "action = ?", "device.assign"))
	require.EqualValues(t, 1, countAudit(t, h, "action = ?", "device.note"))
	require.Zero(t, countAudit(t, h, "action = ?", "POST /api/devices/cli"),
		"the domain entries must replace the middleware fallback")

	var stored model.Device
	require.NoError(t, store.ScopedByOrg(h.db.DB, uint(orgID)).First(&stored, dev.Id).Error)
	require.NotNil(t, stored.OwnerUserID)
	require.EqualValues(t, member.ID, *stored.OwnerUserID)
}

// seedsAdminToken mints a personal token through the same service the router
// derives, holding exactly the given permission codes.
func seedsAdminToken(t *testing.T, h *harness, orgID int64, userID uint, perms ...string) string {
	t.Helper()
	plain, _, err := auth.NewTokenService(h.db.DB, nil).
		Create(context.Background(), userID, uint(orgID), "cli", perms, time.Hour)
	require.NoError(t, err)
	return plain
}
