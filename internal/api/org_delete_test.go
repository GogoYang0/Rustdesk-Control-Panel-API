package api_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/api"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/provision"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

type fakeOrgProvisioner struct {
	failure error
	calls   int
}

func (f *fakeOrgProvisioner) State(context.Context, uint) (provision.State, error) {
	return provision.State{}, nil
}

func (f *fakeOrgProvisioner) SetEnabled(context.Context, uint, uint, bool) (provision.State, bool, error) {
	return provision.State{}, false, nil
}

func (f *fakeOrgProvisioner) Deprovision(context.Context, uint) error {
	f.calls++
	return f.failure
}

func TestDeleteOrg_SoftDeletesAndFreesQuota(t *testing.T) {
	prov := &fakeOrgProvisioner{}
	h := newHarnessWith(t, func(d *api.Deps) {
		d.Provisioning = prov
		d.OrgsPerUser = 1
	})
	h.seedUser(t, "owner@example.com", "password123")
	token := h.login(t, "owner@example.com", "password123")
	orgID := createOrgForTest(t, h, token, "team")
	org := uint(orgID)
	var owner model.User
	require.NoError(t, h.db.DB.Where("email = ?", "owner@example.com").First(&owner).Error)
	require.NoError(t, store.ScopedByOrg(h.db.DB, org).Create(&model.Invitation{
		OrganizationID: org, Email: "invitee@example.com", Role: model.RoleMember,
		TokenHash: strings.Repeat("o", 64), ExpiresAt: time.Now().Add(time.Hour),
	}).Error)
	deviceID := registerDeviceForTest(t, h, token, orgID, "pc", "880001")
	require.NoError(t, store.ScopedByOrg(h.db.DB, org).Create(&model.Ticket{
		OrganizationID: org, DeviceID: uint(deviceID), ActorUserID: owner.ID,
		TokenHash: strings.Repeat("u", 64), ExpiresAt: time.Now().Add(time.Hour),
	}).Error)
	compat := model.CompatSession{
		OrganizationID: org, UserID: owner.ID, JTI: "jti-org-delete",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	require.NoError(t, store.ScopedByOrg(h.db.DB, org).Create(&compat).Error)
	inviteToken := h.newInvitationForTest(t, orgID, "late@example.com", model.RoleMember)

	w := h.do(t, http.MethodDelete, "/api/v1/orgs/"+itoa(orgID), map[string]string{
		"confirm_name": "team",
	}, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Equal(t, 1, prov.calls)

	var deleted model.Organization
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Unscoped().First(&deleted, org).Error)
	require.True(t, deleted.DeletedAt.Valid)
	require.EqualValues(t, owner.ID, deleted.DeletedBy)

	var memberships, invitations, tickets int64
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.Membership{}).
		Where("organization_id = ?", org).Count(&memberships).Error)
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.Invitation{}).
		Where("organization_id = ?", org).Count(&invitations).Error)
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.Ticket{}).
		Where("organization_id = ? AND revoked_at IS NOT NULL", org).Count(&tickets).Error)
	require.Zero(t, memberships)
	require.Zero(t, invitations)
	require.EqualValues(t, 1, tickets)
	var storedCompat model.CompatSession
	require.NoError(t, store.WithoutTenantScope(h.db.DB).First(&storedCompat, compat.ID).Error)
	require.NotNil(t, storedCompat.RevokedAt)

	me := h.do(t, http.MethodGet, "/api/v1/me", nil, token)
	require.Equal(t, http.StatusOK, me.Code)
	require.NotContains(t, me.Body.String(), "team")
	require.Equal(t, http.StatusForbidden,
		h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/members", nil, token).Code)
	require.Equal(t, http.StatusNotFound, h.do(t, http.MethodDelete,
		"/api/v1/orgs/"+itoa(orgID), map[string]string{"confirm_name": "team"}, token).Code)

	// The quota is released and the name is reusable.
	require.Equal(t, http.StatusCreated, h.do(t, http.MethodPost, "/api/v1/orgs",
		map[string]string{"name": "team"}, token).Code)

	// A pending invitation must not re-enter the deleted organization.
	accept := h.do(t, http.MethodPost, "/api/v1/invitations/accept", map[string]string{
		"token": inviteToken, "password": "password123",
	}, "")
	require.Equal(t, http.StatusConflict, accept.Code, accept.Body.String())
}

func TestDeleteOrg_RequiresOwnerAndMatchingName(t *testing.T) {
	prov := &fakeOrgProvisioner{}
	h := newHarnessWith(t, func(d *api.Deps) { d.Provisioning = prov })
	h.seedUser(t, "owner@example.com", "password123")
	h.seedUser(t, "admin@example.com", "password123")
	ownerToken := h.login(t, "owner@example.com", "password123")
	adminToken := h.login(t, "admin@example.com", "password123")
	orgID := createOrgForTest(t, h, ownerToken, "team")
	org := uint(orgID)
	var admin model.User
	require.NoError(t, h.db.DB.Where("email = ?", "admin@example.com").First(&admin).Error)
	addMembership(t, h, org, admin.ID, model.RoleKindAdmin)

	path := "/api/v1/orgs/" + itoa(orgID)
	require.Equal(t, http.StatusBadRequest, h.do(t, http.MethodDelete, path,
		map[string]string{"confirm_name": "wrong"}, ownerToken).Code)
	require.Equal(t, http.StatusForbidden, h.do(t, http.MethodDelete, path,
		map[string]string{"confirm_name": "team"}, adminToken).Code)
	require.Equal(t, 0, prov.calls)

	prov.failure = errors.New("docker down")
	require.Equal(t, http.StatusConflict, h.do(t, http.MethodDelete, path,
		map[string]string{"confirm_name": "team"}, ownerToken).Code)
	var still model.Organization
	require.NoError(t, store.WithoutTenantScope(h.db.DB).First(&still, org).Error)
	require.False(t, still.DeletedAt.Valid)
	var memberships int64
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.Membership{}).
		Where("organization_id = ?", org).Count(&memberships).Error)
	require.EqualValues(t, 2, memberships)
}
