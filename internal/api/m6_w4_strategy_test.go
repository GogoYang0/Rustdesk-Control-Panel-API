package api_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

type strategyView struct {
	Id            int64             `json:"id"`
	Name          string            `json:"name"`
	ConfigOptions map[string]string `json:"config_options"`
	ClearedKeys   []string          `json:"cleared_keys"`
	Version       int64             `json:"version"`
	Enabled       bool              `json:"enabled"`
}

func TestStrategy_CRUD(t *testing.T) {
	h, orgID, _, _, _, _, adminToken, _ := m4Org(t)
	base := "/api/v1/orgs/" + itoa(orgID) + "/strategies"

	w := h.do(t, http.MethodPost, base, map[string]any{
		"name":           "Baseline",
		"config_options": map[string]string{"enable-audio": "N"},
	}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var created strategyView
	decodeData(t, w, &created)
	require.EqualValues(t, 1, created.Version, "a new strategy starts at version 1")
	require.True(t, created.Enabled)
	require.Equal(t, "N", created.ConfigOptions["enable-audio"])

	w = h.do(t, http.MethodGet, base, nil, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var list []strategyView
	decodeData(t, w, &list)
	require.Len(t, list, 1)
	require.Equal(t, "Baseline", list[0].Name)

	item := base + "/" + itoa(created.Id)
	w = h.do(t, http.MethodPatch, item, map[string]any{
		"config_options": map[string]string{"enable-audio": "Y", "enable-clipboard": "N"},
	}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var updated strategyView
	decodeData(t, w, &updated)
	require.EqualValues(t, 2, updated.Version, "changing options must bump the delivery version")
	require.Equal(t, "N", updated.ConfigOptions["enable-clipboard"])

	// A PATCH that changes nothing must not bump the version: every bump costs
	// a re-delivery on each client.
	w = h.do(t, http.MethodPatch, item, map[string]any{
		"config_options": map[string]string{"enable-audio": "Y", "enable-clipboard": "N"},
	}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	decodeData(t, w, &updated)
	require.EqualValues(t, 2, updated.Version)

	// Disabling keeps the row and does not change the version either.
	w = h.do(t, http.MethodPatch, item, map[string]any{"enabled": false}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	decodeData(t, w, &updated)
	require.False(t, updated.Enabled)
	require.EqualValues(t, 2, updated.Version)

	w = h.do(t, http.MethodDelete, item, nil, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = h.do(t, http.MethodGet, base, nil, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	decodeData(t, w, &list)
	require.Empty(t, list)

	// Domain audit rows, and no HTTP-fallback row for the same path: the
	// service writes exactly one entry per mutation.
	var created1, updated1, deleted1, httpRows int64
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.AuditLog{}).
		Where("action = ?", "strategy.create").Count(&created1).Error)
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.AuditLog{}).
		Where("action = ?", "strategy.update").Count(&updated1).Error)
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.AuditLog{}).
		Where("action = ?", "strategy.delete").Count(&deleted1).Error)
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.AuditLog{}).
		Where("action LIKE ?", "PATCH /api/v1/orgs/:orgId/strategies/%").Count(&httpRows).Error)
	require.EqualValues(t, 1, created1)
	require.EqualValues(t, 2, updated1, "the option change and the disable; the repeated patch is a no-op")
	require.EqualValues(t, 1, deleted1)
	require.Zero(t, httpRows)
}

func TestStrategy_RequiresManagePermission(t *testing.T) {
	h, orgID, _, _, _, _, adminToken, memberToken := m4Org(t)
	base := "/api/v1/orgs/" + itoa(orgID) + "/strategies"

	w := h.do(t, http.MethodPost, base, map[string]any{"name": "Ops"}, memberToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	w = h.do(t, http.MethodPost, base, map[string]any{"name": "Ops"}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var created strategyView
	decodeData(t, w, &created)

	// Reading is open to any member: the console renders assignments from it.
	w = h.do(t, http.MethodGet, base, nil, memberToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	item := base + "/" + itoa(created.Id)
	w = h.do(t, http.MethodPatch, item, map[string]any{"enabled": false}, memberToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	w = h.do(t, http.MethodDelete, item, nil, memberToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
}

// TestStrategy_RejectsSystemKeys is the takeover test at the HTTP layer: the
// client applies whatever it receives, so these keys must never be stored.
func TestStrategy_RejectsSystemKeys(t *testing.T) {
	h, orgID, _, _, _, _, adminToken, _ := m4Org(t)
	base := "/api/v1/orgs/" + itoa(orgID) + "/strategies"

	for _, key := range []string{"api-server", "custom-rendezvous-server", "relay-server", "key", "API-SERVER"} {
		w := h.do(t, http.MethodPost, base, map[string]any{
			"name":           "Takeover",
			"config_options": map[string]string{key: "evil.example.com"},
		}, adminToken)
		require.Equal(t, http.StatusBadRequest, w.Code, "key %q must be refused", key)
		require.Contains(t, w.Body.String(), key)
	}

	var rows int64
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.Strategy{}).Count(&rows).Error)
	require.Zero(t, rows, "a refused key must not leave a strategy behind")
}

func TestStrategy_DuplicateNameConflicts(t *testing.T) {
	h, orgID, _, _, _, _, adminToken, _ := m4Org(t)
	base := "/api/v1/orgs/" + itoa(orgID) + "/strategies"

	w := h.do(t, http.MethodPost, base, map[string]any{"name": "Baseline"}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	// Names are unique case-insensitively: the CLI resolves them that way.
	w = h.do(t, http.MethodPost, base, map[string]any{"name": "baseline"}, adminToken)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
}

func TestStrategy_CrossOrgIsNotFound(t *testing.T) {
	h, orgID, _, _, _, _, adminToken, _ := m4Org(t)
	base := "/api/v1/orgs/" + itoa(orgID) + "/strategies"

	w := h.do(t, http.MethodPost, base, map[string]any{"name": "Baseline"}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var created strategyView
	decodeData(t, w, &created)

	// A second organization, with the same caller as a member.
	otherOrgID := createOrg(t, h, adminToken, "strategy-other")
	foreign := "/api/v1/orgs/" + itoa(otherOrgID) + "/strategies/" + itoa(created.Id)
	w = h.do(t, http.MethodPatch, foreign, map[string]any{"enabled": false}, adminToken)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
	w = h.do(t, http.MethodDelete, foreign, nil, adminToken)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
}

func TestStrategy_UpdateRequiresAField(t *testing.T) {
	h, orgID, _, _, _, _, adminToken, _ := m4Org(t)
	base := "/api/v1/orgs/" + itoa(orgID) + "/strategies"

	w := h.do(t, http.MethodPost, base, map[string]any{"name": "Baseline"}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var created strategyView
	decodeData(t, w, &created)

	w = h.do(t, http.MethodPatch, base+"/"+itoa(created.Id), map[string]any{}, adminToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
}

// TestStrategy_GetOne covers the single-read endpoint the contract promises.
func TestStrategy_GetOne(t *testing.T) {
	h, orgID, _, _, _, _, adminToken, memberToken := m4Org(t)
	base := "/api/v1/orgs/" + itoa(orgID) + "/strategies"

	w := h.do(t, http.MethodPost, base, map[string]any{
		"name": "Baseline", "config_options": map[string]string{"enable-audio": "N"},
	}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var created strategyView
	decodeData(t, w, &created)

	w = h.do(t, http.MethodGet, base+"/"+itoa(created.Id), nil, memberToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var got strategyView
	decodeData(t, w, &got)
	require.Equal(t, created.Id, got.Id)
	require.Equal(t, "N", got.ConfigOptions["enable-audio"])

	w = h.do(t, http.MethodGet, base+"/999999", nil, adminToken)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
}

// TestStrategy_RejectsUnknownFields: the client's `extra` map is not part of the
// contract. Silently dropping it would answer 201 for a payload whose options
// were never stored — the same trap the CLI whitelist refuses.
func TestStrategy_RejectsUnknownFields(t *testing.T) {
	h, orgID, _, _, _, _, adminToken, _ := m4Org(t)
	base := "/api/v1/orgs/" + itoa(orgID) + "/strategies"

	w := h.do(t, http.MethodPost, base, map[string]any{
		"name": "Baseline", "extra": map[string]string{"x": "y"},
	}, adminToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "extra")
}

// TestStrategy_ClearedKeysReadBack: a removed key keeps being delivered as an
// empty value; the console needs the list to explain that to the operator.
func TestStrategy_ClearedKeysReadBack(t *testing.T) {
	h, orgID, _, _, _, _, adminToken, _ := m4Org(t)
	base := "/api/v1/orgs/" + itoa(orgID) + "/strategies"

	w := h.do(t, http.MethodPost, base, map[string]any{
		"name":           "Baseline",
		"config_options": map[string]string{"enable-audio": "N", "enable-clipboard": "N"},
	}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var created strategyView
	decodeData(t, w, &created)
	require.Empty(t, created.ClearedKeys)

	w = h.do(t, http.MethodPatch, base+"/"+itoa(created.Id), map[string]any{
		"config_options": map[string]string{"enable-audio": "N"},
	}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var updated strategyView
	decodeData(t, w, &updated)
	require.Equal(t, []string{"enable-clipboard"}, updated.ClearedKeys)
}
