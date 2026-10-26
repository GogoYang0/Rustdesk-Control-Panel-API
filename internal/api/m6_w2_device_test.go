package api_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/access"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// m6DeviceView mirrors the wave-2 fields of the contract's Device schema.
type m6DeviceView struct {
	Id          int64   `json:"id"`
	OwnerUserId *int64  `json:"owner_user_id"`
	OwnerEmail  *string `json:"owner_email"`
	Note        *string `json:"note"`
	Disabled    bool    `json:"disabled"`
}

// m6DevicePath builds the management PATCH addressed by device row id.
func m6DevicePath(orgID, deviceID int64) string {
	return "/api/v1/orgs/" + itoa(orgID) + "/devices/" + itoa(deviceID)
}

func TestUpdateDevice_OwnerRoundTrip(t *testing.T) {
	h, orgID, _, _, member, _, adminToken, _ := m4Org(t)
	dev := createDevice(t, h, orgID, adminToken, "laptop", "w2-1001")
	devicePath := m6DevicePath(orgID, dev.Id)

	w := h.do(t, http.MethodPatch, devicePath, map[string]any{"owner_user_id": member.ID}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var assigned m6DeviceView
	decodeData(t, w, &assigned)
	require.NotNil(t, assigned.OwnerUserId)
	require.EqualValues(t, member.ID, *assigned.OwnerUserId)
	require.NotNil(t, assigned.OwnerEmail, "the response carries the owner address for display")
	require.Equal(t, "m4-member@example.com", *assigned.OwnerEmail)
	require.EqualValues(t, 1, countAudit(t, h, "action = ?", "device.assign"))

	// The list path resolves the same fields with one bulk query and must agree
	// with the single-device response.
	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/devices", nil, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var page struct {
		Items []m6DeviceView `json:"items"`
	}
	decodeData(t, w, &page)
	var listed *m6DeviceView
	for i := range page.Items {
		if page.Items[i].Id == dev.Id {
			listed = &page.Items[i]
		}
	}
	require.NotNil(t, listed, "the created device must appear in the list")
	require.NotNil(t, listed.OwnerUserId)
	require.EqualValues(t, member.ID, *listed.OwnerUserId)
	require.NotNil(t, listed.OwnerEmail)
	require.Equal(t, "m4-member@example.com", *listed.OwnerEmail)

	// JSON null clears the assignment.
	w = h.do(t, http.MethodPatch, devicePath, map[string]any{"owner_user_id": nil}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var cleared m6DeviceView
	decodeData(t, w, &cleared)
	require.Nil(t, cleared.OwnerUserId)
	require.Nil(t, cleared.OwnerEmail)
	require.EqualValues(t, 2, countAudit(t, h, "action = ?", "device.assign"),
		"assigning and clearing are two separate audits")
}

func TestUpdateDevice_DisabledAndOwnerTogether(t *testing.T) {
	h, orgID, _, _, member, _, adminToken, _ := m4Org(t)
	dev := createDevice(t, h, orgID, adminToken, "station", "w2-2001")
	devicePath := m6DevicePath(orgID, dev.Id)

	w := h.do(t, http.MethodPatch, devicePath, map[string]any{
		"disabled":      true,
		"owner_user_id": member.ID,
		"note":          "handed to ops",
	}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var view m6DeviceView
	decodeData(t, w, &view)
	require.True(t, view.Disabled)
	require.NotNil(t, view.OwnerUserId)
	require.EqualValues(t, member.ID, *view.OwnerUserId)
	require.NotNil(t, view.Note)
	require.Equal(t, "handed to ops", *view.Note)

	// One request produces one audit row per changed field.
	require.EqualValues(t, 1, countAudit(t, h, "action = ?", "device.disable"))
	require.EqualValues(t, 1, countAudit(t, h, "action = ?", "device.assign"))
	require.EqualValues(t, 1, countAudit(t, h, "action = ?", "device.note"))

	var stored model.Device
	require.NoError(t, store.ScopedByOrg(h.db.DB, uint(orgID)).First(&stored, dev.Id).Error)
	require.True(t, stored.Disabled)
	require.NotNil(t, stored.OwnerUserID)
	require.EqualValues(t, member.ID, *stored.OwnerUserID)
	require.Equal(t, "handed to ops", stored.Note)
}

func TestUpdateDevice_EmptyBodyRejected(t *testing.T) {
	h, orgID, _, _, _, _, adminToken, _ := m4Org(t)
	dev := createDevice(t, h, orgID, adminToken, "laptop", "w2-3001")
	devicePath := m6DevicePath(orgID, dev.Id)

	w := h.do(t, http.MethodPatch, devicePath, map[string]any{}, adminToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	// A body whose only field is unknown must not be a silent no-op either.
	w = h.do(t, http.MethodPatch, devicePath, map[string]any{"serial": "x"}, adminToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	// A missing body is a malformed request, not an update.
	w = h.do(t, http.MethodPatch, devicePath, nil, adminToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	require.Zero(t, countAudit(t, h, "action IN ?",
		[]string{"device.assign", "device.note", "device.disable", "device.enable"}))
}

// TestUpdateDevice_ReassignMovesVisibility pins Review Focus #1: after a
// device is handed to another member, the previous owner stops reaching it and
// the new owner reaches it — the ownership column feeds the same evaluation the
// client peer list uses.
func TestUpdateDevice_ReassignMovesVisibility(t *testing.T) {
	h, orgID, owner, _, member, _, adminToken, _ := m4Org(t)
	carol := h.seedUser(t, "m6-carol@example.com", "password123")
	seedMember(t, h, orgID, carol.ID, model.RoleMember)

	dev := createDevice(t, h, orgID, adminToken, "carol-laptop", "w2-4001")
	devicePath := m6DevicePath(orgID, dev.Id)

	// The seeded everyone -> all_devices rule makes every device visible and
	// would hide the effect of a reassignment: delete it the way an
	// administrator tightens the organization (D5).
	svc := access.NewService(h.db.DB, audit.NewGormAuditor(h.db.DB), nil)
	ctx := context.Background()
	views, err := svc.ListAccessRules(ctx, uint(orgID))
	require.NoError(t, err)
	for _, view := range views {
		if view.Rule.TargetKind == model.AccessTargetKindAllDevices {
			require.NoError(t, svc.DeleteAccessRule(ctx, uint(orgID), owner.ID, view.Rule.ID))
		}
	}

	// Without its owner the unowned device is reachable by nobody: there stays
	// no implicit visibility.
	all, ids, err := svc.AllowedDeviceIDs(ctx, uint(orgID), member.ID)
	require.NoError(t, err)
	require.False(t, all)
	require.Empty(t, ids)

	w := h.do(t, http.MethodPatch, devicePath, map[string]any{"owner_user_id": member.ID}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	all, ids, err = svc.AllowedDeviceIDs(ctx, uint(orgID), member.ID)
	require.NoError(t, err)
	require.False(t, all)
	require.ElementsMatch(t, []uint{uint(dev.Id)}, ids, "the owner reaches its own device")

	w = h.do(t, http.MethodPatch, devicePath, map[string]any{"owner_user_id": carol.ID}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	all, ids, err = svc.AllowedDeviceIDs(ctx, uint(orgID), member.ID)
	require.NoError(t, err)
	require.False(t, all)
	require.Empty(t, ids, "the previous owner must not keep reaching the device")

	all, ids, err = svc.AllowedDeviceIDs(ctx, uint(orgID), carol.ID)
	require.NoError(t, err)
	require.False(t, all)
	require.ElementsMatch(t, []uint{uint(dev.Id)}, ids, "the new owner reaches the device")
}

func TestUpdateDevice_InvalidOwnerRejected(t *testing.T) {
	h, orgID, _, _, _, _, adminToken, _ := m4Org(t)
	dev := createDevice(t, h, orgID, adminToken, "laptop", "w2-5001")
	devicePath := m6DevicePath(orgID, dev.Id)

	// A user without a membership in this organization can never own a device.
	stranger := h.seedUser(t, "m6-stranger@example.com", "password123")
	w := h.do(t, http.MethodPatch, devicePath, map[string]any{"owner_user_id": stranger.ID}, adminToken)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())

	// 0 is not a user id: clearing goes through JSON null.
	w = h.do(t, http.MethodPatch, devicePath, map[string]any{"owner_user_id": 0}, adminToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	// A malformed value is rejected instead of coerced.
	w = h.do(t, http.MethodPatch, devicePath, map[string]any{"owner_user_id": "abc"}, adminToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	// JSON null is not a boolean: a `{"disabled": null}` that bound as false
	// would silently re-enable a stopped device.
	w = h.do(t, http.MethodPatch, devicePath, map[string]any{"disabled": true}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.do(t, http.MethodPatch, devicePath, map[string]any{"disabled": nil}, adminToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	require.EqualValues(t, 1, countAudit(t, h, "action = ?", "device.disable"))
	require.Zero(t, countAudit(t, h, "action = ?", "device.enable"),
		"a null disabled must not read as an enable")

	// A note longer than the column is refused.
	w = h.do(t, http.MethodPatch, devicePath, map[string]any{"note": strings.Repeat("n", 256)}, adminToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	var stored model.Device
	require.NoError(t, store.ScopedByOrg(h.db.DB, uint(orgID)).First(&stored, dev.Id).Error)
	require.Nil(t, stored.OwnerUserID, "a rejected assignment changes nothing")
	require.Empty(t, stored.Note, "a rejected note changes nothing")
	require.True(t, stored.Disabled, "the null disabled did not re-enable the device")
	// Only the explicit disable above is audited; every rejected request left
	// no trace of its own.
	require.Zero(t, countAudit(t, h, "action IN ?",
		[]string{"device.assign", "device.note", "device.enable"}),
		"a rejected update must not write an audit row")
}

func TestUpdateDevice_MemberForbidden(t *testing.T) {
	h, orgID, _, _, member, _, adminToken, memberToken := m4Org(t)
	dev := createDevice(t, h, orgID, adminToken, "laptop", "w2-6001")

	w := h.do(t, http.MethodPatch, m6DevicePath(orgID, dev.Id),
		map[string]any{"owner_user_id": member.ID, "note": "nope"}, memberToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
}
