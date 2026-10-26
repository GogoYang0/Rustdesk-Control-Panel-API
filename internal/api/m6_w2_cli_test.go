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

// TestAddressBookGrant_UserGroupRoundTrip pins the contract round trip of a
// user_group grant: the request carries subject_group_id, the response echoes
// it, and a group outside the organization is a 404 (never a 400 that would
// distinguish "not yours" from "does not exist").
func TestAddressBookGrant_UserGroupRoundTrip(t *testing.T) {
	h, orgID, _, _, _, _, adminToken, _ := m4Org(t)
	base := "/api/v1/orgs/" + itoa(orgID)

	// A shared book and a user group to grant it to.
	w := h.do(t, http.MethodPost, base+"/address-books",
		map[string]string{"name": "team-book", "scope": "shared"}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var book struct {
		Id int64 `json:"id"`
	}
	decodeData(t, w, &book)

	w = h.do(t, http.MethodPost, base+"/user-groups", map[string]string{"name": "ops"}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var group struct {
		Id int64 `json:"id"`
	}
	decodeData(t, w, &group)

	grantPath := base + "/address-books/" + itoa(book.Id) + "/grants"
	w = h.do(t, http.MethodPost, grantPath, map[string]any{
		"subject_kind": "user_group", "subject_group_id": group.Id, "access": "write",
	}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var grant struct {
		Id           int64  `json:"id"`
		SubjectKind  string `json:"subject_kind"`
		SubjectGroup int64  `json:"subject_group_id"`
		Access       string `json:"access"`
	}
	decodeData(t, w, &grant)
	require.Equal(t, "user_group", grant.SubjectKind)
	require.EqualValues(t, group.Id, grant.SubjectGroup)
	require.Equal(t, "write", grant.Access)

	// The upsert is idempotent on the same subject.
	w = h.do(t, http.MethodPost, grantPath, map[string]any{
		"subject_kind": "user_group", "subject_group_id": group.Id, "access": "full",
	}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var updated struct {
		Id     int64  `json:"id"`
		Access string `json:"access"`
	}
	decodeData(t, w, &updated)
	require.EqualValues(t, grant.Id, updated.Id)
	require.Equal(t, "full", updated.Access)

	// An unknown group id is a not-found, and the negative id is a 400.
	w = h.do(t, http.MethodPost, grantPath, map[string]any{
		"subject_kind": "user_group", "subject_group_id": 999999, "access": "read",
	}, adminToken)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
	w = h.do(t, http.MethodPost, grantPath, map[string]any{
		"subject_kind": "user_group", "subject_group_id": 0, "access": "read",
	}, adminToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	w = h.do(t, http.MethodPost, grantPath, map[string]any{
		"subject_kind": "user_group", "access": "read",
	}, adminToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
}

// TestUserGroupDelete_ReportsCascadedGrants pins the response shape of the
// group deletion after the wave-2 cascade: both counts are reported.
func TestUserGroupDelete_ReportsCascadedGrants(t *testing.T) {
	h, orgID, _, _, _, _, adminToken, _ := m4Org(t)
	base := "/api/v1/orgs/" + itoa(orgID)

	w := h.do(t, http.MethodPost, base+"/address-books",
		map[string]string{"name": "team-book", "scope": "shared"}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var book struct {
		Id int64 `json:"id"`
	}
	decodeData(t, w, &book)

	w = h.do(t, http.MethodPost, base+"/user-groups", map[string]string{"name": "ops"}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var group struct {
		Id int64 `json:"id"`
	}
	decodeData(t, w, &group)

	w = h.do(t, http.MethodPost, base+"/address-books/"+itoa(book.Id)+"/grants", map[string]any{
		"subject_kind": "user_group", "subject_group_id": group.Id, "access": "read",
	}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	w = h.do(t, http.MethodDelete, base+"/user-groups/"+itoa(group.Id), nil, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var data struct {
		RemovedRules  int `json:"removed_rules"`
		RemovedGrants int `json:"removed_grants"`
	}
	decodeData(t, w, &data)
	require.Zero(t, data.RemovedRules)
	require.Equal(t, 1, data.RemovedGrants)
}
