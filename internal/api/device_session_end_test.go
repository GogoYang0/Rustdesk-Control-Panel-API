package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func registerDeviceForTest(t *testing.T, h *harness, token string, orgID int64, name, rid string) int64 {
	t.Helper()
	w := h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/devices", map[string]string{
		"name": name, "rustdesk_id": rid,
	}, token)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var resp struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	return resp.Data.Id
}

func TestDeleteDevice_SoftDeletesAndRevokes(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "owner@example.com", "password123")
	token := h.login(t, "owner@example.com", "password123")
	orgID := createOrgForTest(t, h, token, "team")
	org := uint(orgID)
	deviceID := registerDeviceForTest(t, h, token, orgID, "lab-pc", "700001")
	now := time.Now().UTC()
	compat := model.CompatSession{
		OrganizationID: org, UserID: 1, JTI: "jti-delete-device",
		DeviceID: "700001", ExpiresAt: now.Add(time.Hour),
	}
	require.NoError(t, store.ScopedByOrg(h.db.DB, org).Create(&compat).Error)
	compatID := compat.ID
	require.NoError(t, h.db.DB.Create(&model.DeviceDisconnect{
		OrganizationID: org, DeviceID: uint(deviceID), Reason: "old", RequestedBy: 1,
		Status: model.DisconnectStatusPending, RequestedAt: now, ExpiresAt: now.Add(time.Hour),
	}).Error)
	require.NoError(t, h.db.DB.Create(&model.Ticket{
		OrganizationID: org, DeviceID: uint(deviceID), ActorUserID: 1,
		TokenHash: strings.Repeat("t", 64), ExpiresAt: now.Add(time.Hour),
	}).Error)

	w := h.do(t, http.MethodDelete, "/api/v1/orgs/"+itoa(orgID)+"/devices/"+itoa(deviceID), nil, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var dev model.Device
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Unscoped().First(&dev, deviceID).Error)
	require.True(t, dev.DeletedAt.Valid)
	require.EqualValues(t, 1, dev.DeletedBy)
	require.Empty(t, dev.BoundUUID)
	var storedCompat model.CompatSession
	require.NoError(t, store.WithoutTenantScope(h.db.DB).First(&storedCompat, compatID).Error)
	require.NotNil(t, storedCompat.RevokedAt)
	var disconnect model.DeviceDisconnect
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Where("device_id = ?", deviceID).First(&disconnect).Error)
	require.Equal(t, model.DisconnectStatusExpired, disconnect.Status)
	var ticket model.Ticket
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Where("device_id = ?", deviceID).First(&ticket).Error)
	require.NotNil(t, ticket.RevokedAt)
	var audit model.AuditLog
	require.NoError(t, store.WithoutTenantScope(h.db.DB).
		Where("action = ? AND target_id = ?", "device.delete", itoa(deviceID)).First(&audit).Error)

	list := h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/devices", nil, token)
	require.Equal(t, http.StatusOK, list.Code)
	require.NotContains(t, list.Body.String(), "lab-pc")
}

func TestDeleteDevice_BlocksOpenSessionsAndRestores(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "owner@example.com", "password123")
	token := h.login(t, "owner@example.com", "password123")
	orgID := createOrgForTest(t, h, token, "team")
	org := uint(orgID)
	deviceID := registerDeviceForTest(t, h, token, orgID, "lab-pc", "700002")
	require.NoError(t, h.db.DB.Create(&model.Session{
		OrganizationID: org, DeviceID: uint(deviceID), RustdeskID: "700002",
		Origin: model.SessionOriginNative, Status: model.SessionStatusOpen,
		StartedAt: time.Now().UTC(),
	}).Error)
	require.Equal(t, http.StatusConflict,
		h.do(t, http.MethodDelete, "/api/v1/orgs/"+itoa(orgID)+"/devices/"+itoa(deviceID), nil, token).Code)
	require.NoError(t, store.ScopedByOrg(h.db.DB, org).Model(&model.Session{}).
		Where("device_id = ?", deviceID).Update("status", model.SessionStatusClosed).Error)
	require.Equal(t, http.StatusOK,
		h.do(t, http.MethodDelete, "/api/v1/orgs/"+itoa(orgID)+"/devices/"+itoa(deviceID), nil, token).Code)

	restored := registerDeviceForTest(t, h, token, orgID, "lab-pc-2", "700002")
	require.EqualValues(t, deviceID, restored, "admin re-registration restores the same row")
	var dev model.Device
	require.NoError(t, store.WithoutTenantScope(h.db.DB).First(&dev, deviceID).Error)
	require.False(t, dev.DeletedAt.Valid)
	require.Equal(t, "lab-pc-2", dev.Name)

}

func TestEndSession_ClosesAuditsAndQueuesDisconnect(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "owner@example.com", "password123")
	h.seedUser(t, "member@example.com", "password123")
	token := h.login(t, "owner@example.com", "password123")
	memberToken := h.login(t, "member@example.com", "password123")
	orgID := createOrgForTest(t, h, token, "team")
	org := uint(orgID)
	var member model.User
	require.NoError(t, h.db.DB.Where("email = ?", "member@example.com").First(&member).Error)
	addMembership(t, h, org, member.ID, model.RoleKindMember)
	deviceID := registerDeviceForTest(t, h, token, orgID, "lab-pc", "700003")
	sess := model.Session{
		OrganizationID: org, DeviceID: uint(deviceID), RustdeskID: "700003",
		Origin: model.SessionOriginNative, Status: model.SessionStatusOpen,
		StartedAt: time.Now().UTC(),
	}
	require.NoError(t, h.db.DB.Create(&sess).Error)

	path := "/api/v1/orgs/" + itoa(orgID) + "/sessions/" + itoa(int64(sess.ID)) + "/end"
	require.Equal(t, http.StatusForbidden, h.do(t, http.MethodPost, path, nil, memberToken).Code)
	w := h.do(t, http.MethodPost, path, nil, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp struct {
		Data struct {
			DisconnectRequested bool `json:"disconnect_requested"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.True(t, resp.Data.DisconnectRequested)

	var stored model.Session
	require.NoError(t, store.WithoutTenantScope(h.db.DB).First(&stored, sess.ID).Error)
	require.Equal(t, model.SessionStatusClosed, stored.Status)
	require.NotNil(t, stored.EndedAt)
	require.NotNil(t, stored.EndReason)
	require.Equal(t, model.SessionEndAdminEnded, *stored.EndReason)
	require.EqualValues(t, 1, stored.Revision)
	var event model.SessionEvent
	require.NoError(t, store.WithoutTenantScope(h.db.DB).
		Where("session_id = ? AND kind = ?", sess.ID, model.SessionEndAdminEnded).
		First(&event).Error)
	var audit model.AuditLog
	require.NoError(t, store.WithoutTenantScope(h.db.DB).
		Where("action = ? AND target_id = ?", "session.end", itoa(int64(sess.ID))).First(&audit).Error)
	var disconnect model.DeviceDisconnect
	require.NoError(t, store.WithoutTenantScope(h.db.DB).
		Where("device_id = ? AND status = ?", deviceID, model.DisconnectStatusPending).
		First(&disconnect).Error)

	require.Equal(t, http.StatusConflict, h.do(t, http.MethodPost, path, nil, token).Code)
	require.Equal(t, http.StatusNotFound,
		h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/sessions/999999/end", nil, token).Code)
}
