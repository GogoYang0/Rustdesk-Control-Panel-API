package compatapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/access"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// accessService returns a writable access service on the harness database, so
// the tests can seed groups, rules and the tightened (default-rule deleted)
// state through the real domain paths.
func (h *harness) accessService() *access.Service {
	return access.NewService(h.db.DB, audit.NewGormAuditor(h.db.DB), nil)
}

// tightenAccess deletes the seeded everyone -> all_devices rule (D5).
func tightenAccess(t *testing.T, svc *access.Service, orgID uint) {
	t.Helper()
	ctx := context.Background()
	views, err := svc.ListAccessRules(ctx, orgID)
	require.NoError(t, err)
	for _, view := range views {
		if view.Rule.TargetKind == model.AccessTargetKindAllDevices {
			require.NoError(t, svc.DeleteAccessRule(ctx, orgID, 1, view.Rule.ID))
		}
	}
}

// peersOf reads the compat peer list of one response.
func peersOf(t *testing.T, body []byte) []map[string]any {
	t.Helper()
	var resp struct {
		Peers []map[string]any `json:"peers"`
	}
	require.NoError(t, json.Unmarshal(body, &resp))
	return resp.Peers
}

// TestAccess_PeersHidesUnauthorizedDevices pins D4: an ordinary member's client
// peer list contains only the devices a rule allows; a device in the same
// organization that no rule covers stays invisible.
func TestAccess_PeersHidesUnauthorizedDevices(t *testing.T) {
	h := newHarness(t)
	svc := h.accessService()
	user := h.seedUser(t, "visible@example.com", "password123", true)
	org := h.seedOrg(t, "peers-org")
	h.seedMembershipKind(t, user.ID, org.ID, model.RoleKindMember)
	require.NoError(t, access.Migrate(h.db.DB))
	tightenAccess(t, svc, org.ID)

	ctx := context.Background()
	group, err := svc.CreateUserGroup(ctx, org.ID, user.ID, "ops")
	require.NoError(t, err)
	_, _, err = svc.ReplaceUserGroupMembers(ctx, org.ID, user.ID, group.ID, []uint{user.ID})
	require.NoError(t, err)

	allowed := model.Device{OrganizationID: org.ID, RustdeskID: "111222333", Name: "allowed"}
	require.NoError(t, h.db.DB.Create(&allowed).Error)
	unlisted := model.Device{OrganizationID: org.ID, RustdeskID: "444555666", Name: "unlisted"}
	require.NoError(t, h.db.DB.Create(&unlisted).Error)

	target, err := svc.CreateDeviceGroup(ctx, org.ID, user.ID, "servers")
	require.NoError(t, err)
	_, _, err = svc.ReplaceDeviceGroupDevices(ctx, org.ID, user.ID, target.ID, []uint{allowed.ID})
	require.NoError(t, err)
	_, err = svc.CreateAccessRule(ctx, org.ID, user.ID, group.ID,
		model.AccessTargetKindDeviceGroup, target.ID)
	require.NoError(t, err)

	token, _ := h.login(t, "visible@example.com", "password123", "", "")
	w := h.do(t, http.MethodGet, "/api/peers", nil, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	peers := peersOf(t, w.Body.Bytes())
	require.Len(t, peers, 1, "only the rule-allowed device may appear: %v", peers)
	require.Equal(t, allowed.RustdeskID, peers[0]["id"])
}

// TestAccess_PeersHideDisabledDevices pins D8 for the client list: a disabled
// device is not a peer even for an owner (the management device list remains
// the place where administrators see it).
func TestAccess_PeersHideDisabledDevices(t *testing.T) {
	h := newHarness(t)
	user := h.seedUser(t, "owner-peers@example.com", "password123", true)
	org := h.seedOrg(t, "disabled-peers-org")
	h.seedMembership(t, user.ID, org.ID)
	require.NoError(t, access.Migrate(h.db.DB))

	enabled := model.Device{OrganizationID: org.ID, RustdeskID: "777888999", Name: "enabled"}
	require.NoError(t, h.db.DB.Create(&enabled).Error)
	stopped := model.Device{OrganizationID: org.ID, RustdeskID: "999888777", Name: "stopped", Disabled: true}
	require.NoError(t, h.db.DB.Create(&stopped).Error)

	token, _ := h.login(t, "owner-peers@example.com", "password123", "", "")
	w := h.do(t, http.MethodGet, "/api/peers", nil, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	peers := peersOf(t, w.Body.Bytes())
	require.Len(t, peers, 1, "a disabled device must not be a peer: %v", peers)
	require.Equal(t, enabled.RustdeskID, peers[0]["id"])
}

// TestAccess_AdminSeesAllDevicesInPeers pins Review Focus #5: the bypass runs
// before rule matching, so an admin still sees the whole enabled device set of
// a tightened organization that grants an ordinary member nothing.
func TestAccess_AdminSeesAllDevicesInPeers(t *testing.T) {
	h := newHarness(t)
	svc := h.accessService()
	admin := h.seedUser(t, "admin-peers@example.com", "password123", true)
	member := h.seedUser(t, "member-peers@example.com", "password123", true)
	org := h.seedOrg(t, "admin-peers-org")
	h.seedMembershipKind(t, admin.ID, org.ID, model.RoleKindAdmin)
	h.seedMembershipKind(t, member.ID, org.ID, model.RoleKindMember)
	require.NoError(t, access.Migrate(h.db.DB))
	tightenAccess(t, svc, org.ID)

	for _, id := range []string{"123123123", "321321321"} {
		device := model.Device{OrganizationID: org.ID, RustdeskID: id, Name: id}
		require.NoError(t, h.db.DB.Create(&device).Error)
	}

	memberToken, _ := h.login(t, "member-peers@example.com", "password123", "", "")
	w := h.do(t, http.MethodGet, "/api/peers", nil, memberToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	memberPeers := peersOf(t, w.Body.Bytes())
	require.NotNil(t, memberPeers, "the frozen protocol shape is an array, not null")
	require.Empty(t, memberPeers, "a tightened org grants the ordinary member nothing")

	adminToken, _ := h.login(t, "admin-peers@example.com", "password123", "", "")
	w = h.do(t, http.MethodGet, "/api/peers", nil, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Len(t, peersOf(t, w.Body.Bytes()), 2, "the admin bypass must return the whole enabled set")
}

// TestAccess_PeersDefaultRuleKeepsDevicesVisible pins Review Focus #1 at the
// HTTP layer: an ordinary member of a freshly migrated organization (everyone
// membership is implicit, only the seeded default rule exists) keeps every
// enabled device in the peer list.
func TestAccess_PeersDefaultRuleKeepsDevicesVisible(t *testing.T) {
	h := newHarness(t)
	user := h.seedUser(t, "default-peers@example.com", "password123", true)
	org := h.seedOrg(t, "default-peers-org")
	h.seedMembershipKind(t, user.ID, org.ID, model.RoleKindMember)
	require.NoError(t, access.Migrate(h.db.DB))

	for _, id := range []string{"135791357", "246802468"} {
		device := model.Device{OrganizationID: org.ID, RustdeskID: id, Name: id}
		require.NoError(t, h.db.DB.Create(&device).Error)
	}

	token, _ := h.login(t, "default-peers@example.com", "password123", "", "")
	w := h.do(t, http.MethodGet, "/api/peers", nil, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Len(t, peersOf(t, w.Body.Bytes()), 2, "the migrated default rule must keep every device visible")
}
