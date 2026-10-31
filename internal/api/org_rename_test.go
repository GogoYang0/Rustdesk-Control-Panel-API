package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func createOrgForTest(t *testing.T, h *harness, token, name string) int64 {
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

func orgNameForTest(t *testing.T, h *harness, orgID int64) string {
	t.Helper()
	var org model.Organization
	require.NoError(t, h.db.DB.First(&org, uint(orgID)).Error)
	return org.Name
}

func TestUpdateOrg_RenamesForOwnerAndAudits(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "owner@example.com", "password123")
	token := h.login(t, "owner@example.com", "password123")
	orgID := createOrgForTest(t, h, token, "old-name")

	w := h.do(t, http.MethodPatch, "/api/v1/orgs/"+itoa(orgID), map[string]string{"name": "  new-name  "}, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp struct {
		Data struct {
			Name string `json:"name"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Equal(t, "new-name", resp.Data.Name)
	require.Equal(t, "new-name", orgNameForTest(t, h, orgID))

	var entry model.AuditLog
	require.NoError(t, store.WithoutTenantScope(h.db.DB).
		Where("organization_id = ? AND action = ?", orgID, "organization.rename").
		First(&entry).Error)
	require.Contains(t, entry.Detail, `"old_name":"old-name"`)
	require.Contains(t, entry.Detail, `"new_name":"new-name"`)
}

func TestUpdateOrg_PermissionsAndValidation(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "owner@example.com", "password123")
	h.seedUser(t, "admin@example.com", "password123")
	h.seedUser(t, "member@example.com", "password123")
	h.seedUser(t, "outsider@example.com", "password123")
	ownerToken := h.login(t, "owner@example.com", "password123")
	adminToken := h.login(t, "admin@example.com", "password123")
	memberToken := h.login(t, "member@example.com", "password123")
	outsiderToken := h.login(t, "outsider@example.com", "password123")
	orgID := createOrgForTest(t, h, ownerToken, "team")

	var adminUser model.User
	require.NoError(t, h.db.DB.Where("email = ?", "admin@example.com").First(&adminUser).Error)
	var memberUser model.User
	require.NoError(t, h.db.DB.Where("email = ?", "member@example.com").First(&memberUser).Error)
	require.NoError(t, h.db.DB.Create(&model.Membership{
		OrganizationID: uint(orgID), UserID: adminUser.ID,
		RoleID: h.roleID(t, uint(orgID), model.RoleKindAdmin),
	}).Error)
	require.NoError(t, h.db.DB.Create(&model.Membership{
		OrganizationID: uint(orgID), UserID: memberUser.ID,
		RoleID: h.roleID(t, uint(orgID), model.RoleKindMember),
	}).Error)

	path := "/api/v1/orgs/" + itoa(orgID)
	require.Equal(t, http.StatusForbidden, h.do(t, http.MethodPatch, path, map[string]string{"name": "x"}, adminToken).Code)
	require.Equal(t, http.StatusForbidden, h.do(t, http.MethodPatch, path, map[string]string{"name": "x"}, memberToken).Code)
	require.Equal(t, http.StatusBadRequest, h.do(t, http.MethodPatch, path, map[string]string{"name": "   "}, ownerToken).Code)
	require.Equal(t, http.StatusBadRequest, h.do(t, http.MethodPatch, path, map[string]string{"name": strings.Repeat("维", 129)}, ownerToken).Code)
	// maxLength is on the raw string: a 128-char name with one leading space is 129.
	require.Equal(t, http.StatusBadRequest, h.do(t, http.MethodPatch, path, map[string]string{"name": " " + strings.Repeat("维", 128)}, ownerToken).Code)
	require.Equal(t, http.StatusNotFound, h.do(t, http.MethodPatch, "/api/v1/orgs/9999999", map[string]string{"name": "x"}, ownerToken).Code)
	require.Equal(t, http.StatusUnauthorized, h.do(t, http.MethodPatch, path, map[string]string{"name": "x"}, "").Code)
	require.Equal(t, http.StatusForbidden, h.do(t, http.MethodPatch, path, map[string]string{"name": "x"}, outsiderToken).Code)
	require.Equal(t, "team", orgNameForTest(t, h, orgID))
}

func TestUpdateOrg_AllowsDuplicateAndSameNameNoop(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "owner@example.com", "password123")
	token := h.login(t, "owner@example.com", "password123")
	first := createOrgForTest(t, h, token, "first")
	second := createOrgForTest(t, h, token, "second")

	var before int64
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.AuditLog{}).
		Where("organization_id = ? AND action = ?", first, "organization.rename").
		Count(&before).Error)
	require.Equal(t, http.StatusOK, h.do(t, http.MethodPatch, "/api/v1/orgs/"+itoa(first), map[string]string{"name": "second"}, token).Code)
	require.Equal(t, "second", orgNameForTest(t, h, first))

	// Renaming to the same name is a no-op and does not append another audit row.
	require.Equal(t, http.StatusOK, h.do(t, http.MethodPatch, "/api/v1/orgs/"+itoa(second), map[string]string{"name": "second"}, token).Code)
	var after int64
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.AuditLog{}).
		Where("organization_id = ? AND action = ?", second, "organization.rename").
		Count(&after).Error)
	require.Zero(t, after)
}

func TestCreateOrg_NormalisesName(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "owner@example.com", "password123")
	token := h.login(t, "owner@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "  padded  "}, token)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var resp struct {
		Data struct {
			Name string `json:"name"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Equal(t, "padded", resp.Data.Name)

	require.Equal(t, http.StatusBadRequest,
		h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": strings.Repeat("维", 129)}, token).Code)
}
