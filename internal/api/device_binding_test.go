package api_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/api"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/device"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// newResetHarness wires the device service the way main.go does: the real
// transactional auditor backs the binding reset, so a reset commits its audit
// row or rolls back.
func newResetHarness(t *testing.T, recorder audit.TxRecorder) *harness {
	t.Helper()
	return newHarnessWith(t, func(d *api.Deps) {
		r := recorder
		if r == nil {
			// Mirror main.go: the device service shares the production
			// transactional auditor the harness already wired.
			r, _ = d.Auditor.(audit.TxRecorder)
		}
		d.Devices = device.NewService(d.DB, r, nil)
	})
}

// failingRecorder makes every domain audit write fail, so the handler path for
// an unauditable reset can be exercised.
type failingRecorder struct{}

func (failingRecorder) RecordTx(*gorm.DB, audit.Entry) error {
	return errors.New("audit unavailable")
}

type deviceView struct {
	Id         int64  `json:"id"`
	Name       string `json:"name"`
	RustdeskId string `json:"rustdesk_id"`
	Status     string `json:"status"`
	Bound      bool   `json:"bound"`
	Disabled   bool   `json:"disabled"`
}

func createOrg(t *testing.T, h *harness, token, name string) int64 {
	t.Helper()
	w := h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": name}, token)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var resp struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	return resp.Data.Id
}

func createDevice(t *testing.T, h *harness, orgID int64, token, name, rustdeskID string) deviceView {
	t.Helper()
	w := h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/devices",
		map[string]string{"name": name, "rustdesk_id": rustdeskID}, token)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var resp struct {
		Data deviceView `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	return resp.Data
}

func seedBoundRow(t *testing.T, h *harness, orgID int64, rustdeskID, uuid string) model.Device {
	t.Helper()
	row := model.Device{
		OrganizationID:    uint(orgID),
		RustdeskID:        rustdeskID,
		Name:              rustdeskID,
		BoundUUID:         uuid,
		BindingGeneration: 1,
	}
	require.NoError(t, h.db.DB.Create(&row).Error)
	return row
}

func countAudit(t *testing.T, h *harness, where string, args ...any) int64 {
	t.Helper()
	var n int64
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.AuditLog{}).Where(where, args...).Count(&n).Error)
	return n
}

func TestListDevices_MemberReadsOrgOnly(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "list-owner@example.com", "password123")
	ownerToken := h.login(t, "list-owner@example.com", "password123")
	orgID := createOrg(t, h, ownerToken, "list-devices-org")
	createDevice(t, h, orgID, ownerToken, "Web-01", "1001")
	createDevice(t, h, orgID, ownerToken, "web-02", "1002")

	otherOrg := createOrg(t, h, ownerToken, "list-devices-other")
	createDevice(t, h, otherOrg, ownerToken, "foreign", "2001")

	w := h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/devices", nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp struct {
		Data struct {
			Items    []deviceView `json:"items"`
			Page     int          `json:"page"`
			PageSize int64        `json:"page_size"`
			Total    int64        `json:"total"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.EqualValues(t, 2, resp.Data.Total)
	require.Len(t, resp.Data.Items, 2)
	require.Equal(t, 1, resp.Data.Page)
	require.EqualValues(t, 50, resp.Data.PageSize)
	for _, item := range resp.Data.Items {
		require.NotEqual(t, "foreign", item.Name)
	}

	// A member may read the listing.
	member := h.seedUser(t, "list-member@example.com", "password123")
	require.NoError(t, h.db.DB.Create(&model.Membership{
		OrganizationID: uint(orgID), UserID: member.ID, RoleID: h.roleID(t, uint(orgID), "member"),
	}).Error)
	memberToken := h.login(t, "list-member@example.com", "password123")
	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/devices", nil, memberToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// A non-member is refused.
	h.seedUser(t, "list-outsider@example.com", "password123")
	outsiderToken := h.login(t, "list-outsider@example.com", "password123")
	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/devices", nil, outsiderToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
}

func TestListDevices_QueryAndBoundFilter(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "filter-owner@example.com", "password123")
	token := h.login(t, "filter-owner@example.com", "password123")
	orgID := createOrg(t, h, token, "filter-org")

	createDevice(t, h, orgID, token, "Web-01", "1001")
	bound := createDevice(t, h, orgID, token, "bound-device", "1002")
	require.NoError(t, store.ScopedByOrg(h.db.DB, uint(orgID)).Model(&model.Device{}).Where("id = ?", bound.Id).
		Updates(map[string]any{"bound_uuid": "uuid-1", "binding_generation": 1}).Error)

	w := h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/devices?bound=true", nil, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp struct {
		Data struct {
			Items []deviceView `json:"items"`
			Total int64        `json:"total"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.EqualValues(t, 1, resp.Data.Total)
	require.Len(t, resp.Data.Items, 1)
	require.True(t, resp.Data.Items[0].Bound)
	require.Equal(t, "bound-device", resp.Data.Items[0].Name)

	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/devices?q=WEB", nil, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var byQuery struct {
		Data struct {
			Items []deviceView `json:"items"`
			Total int64        `json:"total"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &byQuery))
	require.EqualValues(t, 1, byQuery.Data.Total)
	require.Len(t, byQuery.Data.Items, 1)
	require.Equal(t, "Web-01", byQuery.Data.Items[0].Name)

	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/devices?pageSize=999", nil, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var clamped struct {
		Data struct {
			PageSize int64 `json:"page_size"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &clamped))
	require.EqualValues(t, 200, clamped.Data.PageSize)

	// q above the contract's maxLength is a client bug, not an empty result.
	long := strings.Repeat("a", 65)
	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/devices?q="+long, nil, token)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
}

func TestListDevices_WritesNoAuditRows(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "quiet-owner@example.com", "password123")
	token := h.login(t, "quiet-owner@example.com", "password123")
	orgID := createOrg(t, h, token, "quiet-org")

	before := countAudit(t, h, "1 = 1")
	for i := 0; i < 2; i++ {
		w := h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/devices", nil, token)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	}
	after := countAudit(t, h, "1 = 1")
	require.EqualValues(t, before, after, "polled reads must not write audit rows")
}

func TestResetDeviceBinding_ResetsAndAuditsOnce(t *testing.T) {
	h := newResetHarness(t, nil)
	h.seedUser(t, "reset-owner@example.com", "password123")
	token := h.login(t, "reset-owner@example.com", "password123")
	orgID := createOrg(t, h, token, "reset-org")
	row := seedBoundRow(t, h, orgID, "884213906", "old-uuid")

	w := h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/devices/"+itoa(int64(row.ID))+"/rebind",
		map[string]string{"reason": "员工换机，旧机已回收"}, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var resp struct {
		Data deviceView `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.False(t, resp.Data.Bound, "the response must show the binding cleared")

	var stored model.Device
	require.NoError(t, store.ScopedByOrg(h.db.DB, uint(orgID)).First(&stored, row.ID).Error)
	require.Equal(t, "", stored.BoundUUID)
	require.EqualValues(t, 2, stored.BindingGeneration)

	require.EqualValues(t, 1, countAudit(t, h, "action = ?", "device.binding.reset"))
	require.EqualValues(t, 0, countAudit(t, h, "action LIKE ?", "%/rebind%"),
		"the domain entry must suppress the request-level fallback")
}

func TestResetDeviceBinding_RejectsBlankReasonAcceptRunes(t *testing.T) {
	h := newResetHarness(t, nil)
	h.seedUser(t, "reason-owner@example.com", "password123")
	token := h.login(t, "reason-owner@example.com", "password123")
	orgID := createOrg(t, h, token, "reason-org")
	row := seedBoundRow(t, h, orgID, "1001", "old-uuid")
	path := "/api/v1/orgs/" + itoa(orgID) + "/devices/" + itoa(int64(row.ID)) + "/rebind"

	w := h.do(t, http.MethodPost, path, map[string]string{"reason": "   "}, token)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	w = h.do(t, http.MethodPost, path, map[string]string{"reason": strings.Repeat("换", 501)}, token)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	w = h.do(t, http.MethodPost, path, map[string]string{"reason": strings.Repeat("换", 500)}, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

func TestResetDeviceBinding_PermissionsAndNotFound(t *testing.T) {
	h := newResetHarness(t, nil)
	h.seedUser(t, "perm-owner@example.com", "password123")
	token := h.login(t, "perm-owner@example.com", "password123")
	orgID := createOrg(t, h, token, "perm-org")
	row := seedBoundRow(t, h, orgID, "1001", "old-uuid")
	path := "/api/v1/orgs/" + itoa(orgID) + "/devices/" + itoa(int64(row.ID)) + "/rebind"

	member := h.seedUser(t, "perm-member@example.com", "password123")
	require.NoError(t, h.db.DB.Create(&model.Membership{
		OrganizationID: uint(orgID), UserID: member.ID, RoleID: h.roleID(t, uint(orgID), "member"),
	}).Error)
	memberToken := h.login(t, "perm-member@example.com", "password123")
	w := h.do(t, http.MethodPost, path, map[string]string{"reason": "越权"}, memberToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	w = h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/devices/999999/rebind",
		map[string]string{"reason": "不存在"}, token)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())

	otherOrg := createOrg(t, h, token, "perm-other-org")
	foreign := seedBoundRow(t, h, otherOrg, "2001", "other-uuid")
	w = h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/devices/"+itoa(int64(foreign.ID))+"/rebind",
		map[string]string{"reason": "跨组织"}, token)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
}

func TestResetDeviceBinding_AuditFailureIs500(t *testing.T) {
	h := newResetHarness(t, failingRecorder{})
	h.seedUser(t, "audit-owner@example.com", "password123")
	token := h.login(t, "audit-owner@example.com", "password123")
	orgID := createOrg(t, h, token, "audit-org")
	row := seedBoundRow(t, h, orgID, "1001", "old-uuid")

	w := h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/devices/"+itoa(int64(row.ID))+"/rebind",
		map[string]string{"reason": "员工换机"}, token)
	require.Equal(t, http.StatusInternalServerError, w.Code, w.Body.String())

	var stored model.Device
	require.NoError(t, store.ScopedByOrg(h.db.DB, uint(orgID)).First(&stored, row.ID).Error)
	require.Equal(t, "old-uuid", stored.BoundUUID, "an unaudited reset must roll back")
	require.EqualValues(t, 1, stored.BindingGeneration)
}
