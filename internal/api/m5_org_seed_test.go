package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// TestAccess_CreateOrgSeedsDefaults pins the creation-time half of the
// migration: an organization created after v0.9.0 must get the same everyone
// group and everyone -> all_devices rule as migrated organizations, in the
// creation transaction, so its members never see an empty device list.
func TestAccess_CreateOrgSeedsDefaults(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "seedorg@example.com", "password123")
	token := h.login(t, "seedorg@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "seed-org"}, token)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	var resp struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	orgID := uint(resp.Data.Id)
	var groups []model.UserGroup
	require.NoError(t, store.ScopedByOrg(h.db.DB, orgID).
		Where("kind = ?", model.UserGroupKindEveryone).Find(&groups).Error)
	require.Len(t, groups, 1)
	require.Equal(t, "everyone", groups[0].Name)

	var rules []model.AccessRule
	require.NoError(t, store.ScopedByOrg(h.db.DB, orgID).Find(&rules).Error)
	require.Len(t, rules, 1)
	require.Equal(t, groups[0].ID, rules[0].SourceGroupID)
	require.Equal(t, model.AccessTargetKindAllDevices, rules[0].TargetKind)
}
