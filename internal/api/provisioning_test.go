package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/api"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/provision"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// fakeProvisioningManager isolates the HTTP layer from docker and the database;
// the service behaviour is covered by internal/provision tests.
type fakeProvisioningManager struct {
	state   provision.State
	changed bool
	err     error
	calls   []fakeProvisioningCall
}

type fakeProvisioningCall struct {
	orgID   uint
	actorID uint
	enabled bool
}

func (f *fakeProvisioningManager) State(_ context.Context, _ uint) (provision.State, error) {
	return f.state, f.err
}

func (f *fakeProvisioningManager) SetEnabled(_ context.Context, orgID, actorID uint, enabled bool) (provision.State, bool, error) {
	f.calls = append(f.calls, fakeProvisioningCall{orgID: orgID, actorID: actorID, enabled: enabled})
	if f.err != nil {
		return provision.State{}, false, f.err
	}
	return f.state, f.changed, nil
}

// fakeProvisionQueue records enqueues and can simulate a full queue.
type fakeProvisionQueue struct {
	enqueued []uint
	err      error
}

func (f *fakeProvisionQueue) Enqueue(orgID uint) error {
	if f.err != nil {
		return f.err
	}
	f.enqueued = append(f.enqueued, orgID)
	return nil
}

func addMember(t *testing.T, h *harness, orgID int64, user model.User, role string) {
	t.Helper()
	require.NoError(t, h.db.DB.Create(&model.Membership{
		OrganizationID: uint(orgID),
		UserID:         user.ID,
		RoleID:         h.roleID(t, uint(orgID), role),
	}).Error)
}

func countAuditAction(t *testing.T, h *harness, action string) int64 {
	t.Helper()
	var n int64
	require.NoError(t, store.WithoutTenantScope(h.db.DB).
		Model(&model.AuditLog{}).
		Where("action = ?", action).
		Count(&n).Error)
	return n
}

type provisioningView struct {
	Enabled        bool   `json:"enabled"`
	State          string `json:"state"`
	CleanupPending bool   `json:"cleanup_pending"`
}

// newProvisioningHarness wires the real service the way main.go does, so the
// disable endpoint commits the flag and its audit row in one transaction.
func newProvisioningHarness(t *testing.T) *harness {
	t.Helper()
	h := newHarnessWith(t, func(d *api.Deps) {
		recorder, _ := d.Auditor.(audit.TxRecorder)
		svc := provision.NewService(
			d.DB,
			provision.NewPortPool(d.DB, 21116, 22115),
			&provision.MockOrchestrator{},
			recorder,
			nil,
			provision.Config{Image: "test", RelayHost: "relay.test", PortStart: 21116, PortEnd: 22115},
		)
		svc.SetPortChecker(func(uint16, string) error { return nil })
		d.Provisioning = svc
	})
	require.NoError(t, h.db.DB.AutoMigrate(&model.ServerGroup{}))
	return h
}

func TestGetProvisioning_OwnerOnly(t *testing.T) {
	mgr := &fakeProvisioningManager{state: provision.State{Enabled: true, Status: provision.StatusPending}}
	h := newHarnessWith(t, func(d *api.Deps) { d.Provisioning = mgr })

	owner := h.seedUser(t, "owner@example.com", "password123")
	admin := h.seedUser(t, "admin@example.com", "password123")
	member := h.seedUser(t, "member@example.com", "password123")
	ownerToken := h.login(t, owner.Email, "password123")
	adminToken := h.login(t, admin.Email, "password123")
	memberToken := h.login(t, member.Email, "password123")
	orgID := createOrg(t, h, ownerToken, "acme")
	addMember(t, h, orgID, admin, model.RoleAdmin)
	addMember(t, h, orgID, member, model.RoleMember)

	path := "/api/v1/orgs/" + itoa(orgID) + "/provisioning"

	w := h.do(t, http.MethodGet, path, nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp struct {
		Data provisioningView `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.True(t, resp.Data.Enabled)
	require.Equal(t, provision.StatusPending, resp.Data.State)
	require.False(t, resp.Data.CleanupPending)

	require.Equal(t, http.StatusForbidden, h.do(t, http.MethodGet, path, nil, adminToken).Code)
	require.Equal(t, http.StatusForbidden, h.do(t, http.MethodGet, path, nil, memberToken).Code)
	require.Equal(t, http.StatusForbidden,
		h.do(t, http.MethodPut, path, map[string]any{"enabled": false}, adminToken).Code)
	require.Equal(t, http.StatusUnauthorized, h.do(t, http.MethodGet, path, nil, "").Code)
	require.Equal(t, http.StatusBadRequest,
		h.do(t, http.MethodGet, "/api/v1/orgs/0/provisioning", nil, ownerToken).Code)
}

func TestGetProvisioning_ReportsCleanupPending(t *testing.T) {
	mgr := &fakeProvisioningManager{state: provision.State{
		Enabled:        false,
		Status:         provision.StatusDisabled,
		CleanupPending: true,
	}}
	h := newHarnessWith(t, func(d *api.Deps) { d.Provisioning = mgr })
	owner := h.seedUser(t, "owner@example.com", "password123")
	token := h.login(t, owner.Email, "password123")
	orgID := createOrg(t, h, token, "acme")

	w := h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/provisioning", nil, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp struct {
		Data provisioningView `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.False(t, resp.Data.Enabled)
	require.Equal(t, provision.StatusDisabled, resp.Data.State)
	require.True(t, resp.Data.CleanupPending,
		"disabled intent must be distinguishable from confirmed teardown")
}

func TestUpdateProvisioning_DisableWritesAudit(t *testing.T) {
	h := newProvisioningHarness(t)
	owner := h.seedUser(t, "owner@example.com", "password123")
	token := h.login(t, owner.Email, "password123")
	orgID := createOrg(t, h, token, "acme")

	w := h.do(t, http.MethodPut, "/api/v1/orgs/"+itoa(orgID)+"/provisioning",
		map[string]any{"enabled": false}, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var resp struct {
		Data provisioningView `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.False(t, resp.Data.Enabled)
	require.Equal(t, provision.StatusDisabled, resp.Data.State)

	var org model.Organization
	require.NoError(t, h.db.DB.First(&org, orgID).Error)
	require.True(t, org.ProvisioningDisabled)
	require.EqualValues(t, 1, countAuditAction(t, h, "organization.provisioning.update"),
		"the domain audit entry commits with the flag")
}

func TestUpdateProvisioning_EnableEnqueues(t *testing.T) {
	mgr := &fakeProvisioningManager{
		state:   provision.State{Enabled: true, Status: provision.StatusPending},
		changed: true,
	}
	queue := &fakeProvisionQueue{}
	h := newHarnessWith(t, func(d *api.Deps) {
		d.Provisioning = mgr
		d.ProvisionQueue = queue
	})
	owner := h.seedUser(t, "owner@example.com", "password123")
	token := h.login(t, owner.Email, "password123")
	orgID := createOrg(t, h, token, "acme")
	// Organization creation already enqueues once; only the switch call is
	// under test here.
	queue.enqueued = nil

	w := h.do(t, http.MethodPut, "/api/v1/orgs/"+itoa(orgID)+"/provisioning",
		map[string]any{"enabled": true}, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Equal(t, []uint{uint(orgID)}, queue.enqueued)
	require.Len(t, mgr.calls, 1)
	require.Equal(t, uint(orgID), mgr.calls[0].orgID)
	require.Equal(t, owner.ID, mgr.calls[0].actorID)
	require.True(t, mgr.calls[0].enabled)
}

func TestUpdateProvisioning_Idempotent(t *testing.T) {
	mgr := &fakeProvisioningManager{
		state:   provision.State{Enabled: true, Status: model.ServerGroupDeployed},
		changed: false,
	}
	queue := &fakeProvisionQueue{}
	h := newHarnessWith(t, func(d *api.Deps) {
		d.Provisioning = mgr
		d.ProvisionQueue = queue
	})
	owner := h.seedUser(t, "owner@example.com", "password123")
	token := h.login(t, owner.Email, "password123")
	orgID := createOrg(t, h, token, "acme")
	// Organization creation already enqueued once; a no-op switch must not add
	// another job.
	queue.enqueued = nil

	w := h.do(t, http.MethodPut, "/api/v1/orgs/"+itoa(orgID)+"/provisioning",
		map[string]any{"enabled": true}, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Empty(t, queue.enqueued, "a no-op must not enqueue again")
	require.Zero(t, countAuditAction(t, h, "organization.provisioning.update"),
		"a no-op has no domain audit; the middleware still records the request")
}

func TestUpdateProvisioning_BadBody(t *testing.T) {
	mgr := &fakeProvisioningManager{state: provision.State{Enabled: true, Status: provision.StatusPending}}
	h := newHarnessWith(t, func(d *api.Deps) { d.Provisioning = mgr })
	owner := h.seedUser(t, "owner@example.com", "password123")
	token := h.login(t, owner.Email, "password123")
	orgID := createOrg(t, h, token, "acme")

	w := h.do(t, http.MethodPut, "/api/v1/orgs/"+itoa(orgID)+"/provisioning",
		map[string]any{}, token)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	require.Empty(t, mgr.calls)
}

func TestProvisioning_Unavailable(t *testing.T) {
	h := newHarness(t)
	owner := h.seedUser(t, "owner@example.com", "password123")
	token := h.login(t, owner.Email, "password123")
	orgID := createOrg(t, h, token, "acme")
	path := "/api/v1/orgs/" + itoa(orgID) + "/provisioning"

	require.Equal(t, http.StatusInternalServerError, h.do(t, http.MethodGet, path, nil, token).Code)
	require.Equal(t, http.StatusInternalServerError,
		h.do(t, http.MethodPut, path, map[string]any{"enabled": true}, token).Code)
}

func TestUpdateProvisioning_QueueFullStillOK(t *testing.T) {
	mgr := &fakeProvisioningManager{
		state:   provision.State{Enabled: true, Status: provision.StatusPending},
		changed: true,
	}
	queue := &fakeProvisionQueue{err: provision.ErrQueueFull}
	h := newHarnessWith(t, func(d *api.Deps) {
		d.Provisioning = mgr
		d.ProvisionQueue = queue
	})
	owner := h.seedUser(t, "owner@example.com", "password123")
	token := h.login(t, owner.Email, "password123")
	orgID := createOrg(t, h, token, "acme")

	w := h.do(t, http.MethodPut, "/api/v1/orgs/"+itoa(orgID)+"/provisioning",
		map[string]any{"enabled": true}, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}
