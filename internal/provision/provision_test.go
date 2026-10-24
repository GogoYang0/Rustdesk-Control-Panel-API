package provision_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/provision"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

const (
	testPortStart = 21116
	testPortEnd   = 22115
)

type fixture struct {
	st       store.Store
	pool     *provision.PortPool
	orch     *provision.MockOrchestrator
	svc      *provision.Service
	recorder *fakeRecorder
	logs     *bytes.Buffer
	dataDir  string
}

// fakeRecorder captures the audit entries written inside a transaction and can
// simulate an audit outage, which must roll the transaction back.
type fakeRecorder struct {
	mu      sync.Mutex
	entries []audit.Entry
	fail    error
}

func newFakeRecorder() *fakeRecorder { return &fakeRecorder{} }

func (f *fakeRecorder) RecordTx(_ *gorm.DB, e audit.Entry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	f.entries = append(f.entries, e)
	return nil
}

func (f *fakeRecorder) snapshot() []audit.Entry {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]audit.Entry, len(f.entries))
	copy(out, f.entries)
	return out
}

func (f *fakeRecorder) actions() []string {
	entries := f.snapshot()
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Action)
	}
	return out
}

func (f *fakeRecorder) setFail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail = err
}

func (f *fakeRecorder) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries = nil
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	return newFixtureWithRecorder(t, newFakeRecorder())
}

func newFixtureWithRecorder(t *testing.T, recorder *fakeRecorder) *fixture {
	t.Helper()
	dsn := fmt.Sprintf("file:prov_%d?mode=memory&cache=shared", time.Now().UnixNano())
	st, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	require.NoError(t, st.DB.AutoMigrate(&model.Organization{}, &model.ServerGroup{}))

	buf := &bytes.Buffer{}
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		zapcore.AddSync(buf),
		zapcore.DebugLevel,
	)

	orch := &provision.MockOrchestrator{}
	pool := provision.NewPortPool(st.DB, testPortStart, testPortEnd)
	dataDir := t.TempDir()
	// A typed nil pointer would still satisfy the interface, so only assign the
	// fake when the test asked for a recorder.
	var rec audit.TxRecorder
	if recorder != nil {
		rec = recorder
	}
	svc := provision.NewService(st.DB, pool, orch, rec, zap.New(core), provision.Config{
		Image:     "rustdesk/rustdesk-server:test",
		RelayHost: "relay.test",
		DataDir:   dataDir,
		PortStart: testPortStart,
		PortEnd:   testPortEnd,
	})
	// Tests must not depend on the host's port state; conflict cases replace
	// this checker explicitly.
	svc.SetPortChecker(func(uint16, string) error { return nil })
	return &fixture{
		st:       *st,
		pool:     pool,
		orch:     orch,
		dataDir:  dataDir,
		recorder: recorder,
		svc:      svc,
		logs:     buf,
	}
}

func (f *fixture) org(t *testing.T, name string) model.Organization {
	t.Helper()
	o := model.Organization{Name: name}
	require.NoError(t, f.st.DB.Create(&o).Error)
	return o
}

func TestPortPool_ConcurrentAllocate_NoDup(t *testing.T) {
	f := newFixture(t)

	const orgs = 20
	ids := make([]uint, orgs)
	for i := 0; i < orgs; i++ {
		ids[i] = f.org(t, fmt.Sprintf("org-%d", i)).ID
	}

	var wg sync.WaitGroup
	results := make([]*model.ServerGroup, orgs)
	errs := make([]error, orgs)
	for i := 0; i < orgs; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = f.pool.Allocate(ids[i])
		}(i)
	}
	wg.Wait()

	seen := map[string]bool{}
	for i := 0; i < orgs; i++ {
		require.NoError(t, errs[i])
		require.NotNil(t, results[i])
		key := fmt.Sprintf("%d-%d", results[i].HbbsPort, results[i].HbbrPort)
		require.False(t, seen[key], "duplicate port pair %s", key)
		seen[key] = true
		require.EqualValues(t, results[i].HbbsPort+3, results[i].HbbrPort, "hbbs owns three host ports before hbbr starts")
	}
}

// A second allocation for the same org must fail fast, not scan the whole pool.
func TestPortPool_SecondAllocateForSameOrg_ReportsConflict(t *testing.T) {
	f := newFixture(t)
	org := f.org(t, "same-org")

	_, err := f.pool.Allocate(org.ID)
	require.NoError(t, err)

	_, err = f.pool.Allocate(org.ID)
	require.ErrorIs(t, err, provision.ErrProvisioningInProgress)
	require.NotErrorIs(t, err, provision.ErrPortPoolExhausted)
}

func TestProvision_FailureRollsBack(t *testing.T) {
	f := newFixture(t)
	org := f.org(t, "rollback-org")
	f.orch.FailWith = errors.New("docker unavailable")

	_, err := f.svc.ProvisionForOrg(context.Background(), org.ID)
	require.Error(t, err)

	var count int64
	require.NoError(t, store.ScopedByOrg(f.st.DB, org.ID).Model(&model.ServerGroup{}).Count(&count).Error)
	require.Zero(t, count, "a clean rollback removes the row and frees the ports")
	require.Contains(t, f.orch.Removed, fmt.Sprintf("panel-org-%d", org.ID))

	f.orch.FailWith = nil
	row, err := f.svc.ProvisionForOrg(context.Background(), org.ID)
	require.NoError(t, err)
	require.EqualValues(t, testPortStart, row.HbbsPort)
	require.Equal(t, model.ServerGroupDeployed, row.State)
}

// When cleanup itself fails the row must stay in the failed state so the ports
// are not handed to another organization.
func TestProvision_CleanupFailure_KeepsPortsReserved(t *testing.T) {
	f := newFixture(t)
	org := f.org(t, "stuck-org")
	f.orch.FailWith = errors.New("docker unavailable")
	f.orch.RemoveErr = errors.New("cannot remove container")

	_, err := f.svc.ProvisionForOrg(context.Background(), org.ID)
	require.Error(t, err)

	var row model.ServerGroup
	require.NoError(t, store.ScopedByOrg(f.st.DB, org.ID).First(&row).Error)
	require.Equal(t, model.ServerGroupFailed, row.State)
	require.NotEmpty(t, row.LastError)

	// Ports stay reserved, so a retry reports a pending record instead of
	// silently reusing them.
	f.orch.FailWith = nil
	f.orch.RemoveErr = nil
	_, err = f.svc.ProvisionForOrg(context.Background(), org.ID)
	require.ErrorIs(t, err, provision.ErrProvisioningInProgress)
}

// Cleanup must not inherit an already-cancelled deploy context.
func TestProvision_CleanupUsesLiveContext(t *testing.T) {
	f := newFixture(t)
	org := f.org(t, "cancel-org")
	f.orch.FailWith = errors.New("deploy timed out")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := f.svc.ProvisionForOrg(ctx, org.ID)
	require.Error(t, err)
	require.NotContains(t, f.orch.Removed, "", "remove was attempted")
	require.Contains(t, f.orch.Removed, fmt.Sprintf("panel-org-%d", org.ID),
		"rollback must run with a live context, not the cancelled one")
}

func TestProvision_SuccessStoresPublicKeyOnly(t *testing.T) {
	f := newFixture(t)
	org := f.org(t, "success-org")

	row, err := f.svc.ProvisionForOrg(context.Background(), org.ID)
	require.NoError(t, err)
	require.NotEmpty(t, row.PubKey)
	require.NotEmpty(t, row.Fingerprint)
	require.NotEmpty(t, row.ConfigSnapshot)
	require.NotContains(t, row.ConfigSnapshot, "PRIVATE KEY")
	// The snapshot records the whole block so clients can be pointed at it.
	// 21118 is the hbbs websocket, 21119 the hbbr websocket.
	require.Contains(t, row.ConfigSnapshot, fmt.Sprintf(`"hbbs_ws_port":%d`, row.HbbsPort+2))
	require.Contains(t, row.ConfigSnapshot, fmt.Sprintf(`"hbbr_ws_port":%d`, row.HbbrPort+1))

	require.Len(t, f.orch.Deployed, 1)
	require.NotEmpty(t, f.orch.Deployed[0].PrivateKey, "the key pair must reach the orchestrator")
	require.NotContains(t, f.logs.String(), f.orch.Deployed[0].PrivateKey,
		"the private key must never be logged")

	_, err = f.svc.ProvisionForOrg(context.Background(), org.ID)
	require.ErrorIs(t, err, provision.ErrAlreadyProvisioned)
}

func TestDeprovision_FreesPorts(t *testing.T) {
	f := newFixture(t)
	org := f.org(t, "deprovision-org")

	row, err := f.svc.ProvisionForOrg(context.Background(), org.ID)
	require.NoError(t, err)
	require.NoError(t, f.svc.Deprovision(context.Background(), org.ID))

	var count int64
	require.NoError(t, store.ScopedByOrg(f.st.DB, org.ID).Model(&model.ServerGroup{}).Count(&count).Error)
	require.Zero(t, count)

	next := f.org(t, "next-org")
	again, err := f.svc.ProvisionForOrg(context.Background(), next.ID)
	require.NoError(t, err)
	require.Equal(t, row.HbbsPort, again.HbbsPort)
}

// A changed provision.portStart must not hand out overlapping blocks: the two
// unique indexes alone would accept 21117 after 21116, yet the host would then
// bind 21117..21120 twice.
func TestPortPool_ShiftedStartSkipsOverlappingBlocks(t *testing.T) {
	f := newFixture(t)

	first := f.org(t, "first-org")
	block, err := f.pool.Allocate(first.ID)
	require.NoError(t, err)
	require.EqualValues(t, testPortStart, block.HbbsPort)

	// Same range, one port later, as if provision.portStart had changed.
	shifted := provision.NewPortPool(f.st.DB, testPortStart+1, testPortEnd)
	second := f.org(t, "second-org")
	next, err := shifted.Allocate(second.ID)
	require.NoError(t, err)
	require.EqualValues(t, testPortStart+provision.PortBlockSize+1, next.HbbsPort,
		"the overlapping block must be skipped entirely")

	// When every block in range overlaps, allocation fails instead of
	// producing a partial overlap.
	tiny := provision.NewPortPool(f.st.DB, testPortStart+1, testPortStart+5)
	third := f.org(t, "third-org")
	_, err = tiny.Allocate(third.ID)
	require.ErrorIs(t, err, provision.ErrPortPoolExhausted)
}

// Reconciliation treats the organization row as the durable provisioning
// intent: every organization without a server group is queued exactly once.
func TestReconcile_EnqueuesOnlyUnprovisionedOrgs(t *testing.T) {
	f := newFixture(t)
	done := f.org(t, "done-org")
	pending := f.org(t, "pending-org")

	_, err := f.svc.ProvisionForOrg(context.Background(), done.ID)
	require.NoError(t, err)

	queue := provision.NewQueue(f.svc, 1, 4, nil)
	queued, err := queue.Reconcile(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, queued, "only the organization without a server group is queued")

	// Once the pending organization is provisioned it must not be queued again.
	_, err = f.svc.ProvisionForOrg(context.Background(), pending.ID)
	require.NoError(t, err)
	queued, err = queue.Reconcile(context.Background())
	require.NoError(t, err)
	require.Zero(t, queued)
}

// Removing the deployment on purpose must not be undone by the reconciler: the
// organization has no server group row afterwards, so the intent has to be
// recorded on the organization itself.
func TestDeprovision_IsNotReconciled(t *testing.T) {
	f := newFixture(t)
	org := f.org(t, "leaving-org")

	_, err := f.svc.ProvisionForOrg(context.Background(), org.ID)
	require.NoError(t, err)
	require.NoError(t, f.svc.Deprovision(context.Background(), org.ID))

	queue := provision.NewQueue(f.svc, 1, 4, nil)
	queued, err := queue.Reconcile(context.Background())
	require.NoError(t, err)
	require.Zero(t, queued, "a deliberate deprovision must not be re-provisioned")

	ids, _, err := f.svc.PendingOrgIDs(context.Background(), 0, 10)
	require.NoError(t, err)
	require.Empty(t, ids)

	// An explicit provisioning request still works after a deprovision.
	_, err = f.svc.ProvisionForOrg(context.Background(), org.ID)
	require.NoError(t, err)
}

// Deprovisioning an organization that has no server group row must still record
// the intent, otherwise the reconciler provisions it right away.
func TestDeprovision_WithoutRowStillMarksDisabled(t *testing.T) {
	f := newFixture(t)
	org := f.org(t, "queued-org") // provisioning is still queued, no row yet

	require.NoError(t, f.svc.Deprovision(context.Background(), org.ID))

	queue := provision.NewQueue(f.svc, 1, 4, nil)
	queued, err := queue.Reconcile(context.Background())
	require.NoError(t, err)
	require.Zero(t, queued, "a deprovision before the first deploy must stick")
}

// A job that was enqueued before the removal must not undo it.
func TestProvisionQueued_RespectsDeprovision(t *testing.T) {
	f := newFixture(t)
	org := f.org(t, "removed-org")

	_, err := f.svc.ProvisionForOrg(context.Background(), org.ID)
	require.NoError(t, err)
	require.NoError(t, f.svc.Deprovision(context.Background(), org.ID))

	_, err = f.svc.ProvisionQueued(context.Background(), org.ID)
	require.ErrorIs(t, err, provision.ErrProvisioningDisabled)
	require.Len(t, f.orch.Deployed, 1, "the deprovisioned organization must not be deployed again")
}

// Two workers racing for the same organization must report an organization
// conflict, never a bogus port pool exhaustion.
func TestPortPool_ConcurrentAllocateSameOrg_ReportsConflict(t *testing.T) {
	f := newFixture(t)
	org := f.org(t, "race-org")

	const attempts = 8
	errs := make(chan error, attempts)
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.pool.Allocate(org.ID)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)

	won, conflict := 0, 0
	for err := range errs {
		switch {
		case err == nil:
			won++
		case errors.Is(err, provision.ErrAlreadyProvisioned), errors.Is(err, provision.ErrProvisioningInProgress):
			conflict++
		default:
			require.Failf(t, "unexpected error", "%v", err)
		}
	}
	require.Equal(t, 1, won, "exactly one allocation may win")
	require.Equal(t, attempts-1, conflict)
}

// The queue notifies the deployment hook once per successful provisioning so
// the log collector starts tailing the new containers immediately.
func TestQueue_NotifiesAfterProvisioning(t *testing.T) {
	f := newFixture(t)
	org := f.org(t, "hooked-org")

	queue := provision.NewQueue(f.svc, 1, 4, zap.NewNop())
	notified := make(chan uint, 4)
	queue.OnProvisioned(func(orgID uint) { notified <- orgID })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	queue.Start(ctx)

	require.NoError(t, queue.Enqueue(org.ID))
	select {
	case got := <-notified:
		require.Equal(t, org.ID, got)
	case <-time.After(5 * time.Second):
		t.Fatal("the provisioning hook was not called")
	}
	require.Len(t, f.orch.Deployed, 1)
}

// After a successful deprovision the containers are gone, so anything following
// them has to stop: the log collector registers its Unwatch here.
func TestDeprovision_NotifiesHook(t *testing.T) {
	f := newFixture(t)
	org := f.org(t, "acme")
	_, err := f.svc.ProvisionForOrg(context.Background(), org.ID)
	require.NoError(t, err)

	var got []uint
	f.svc.OnDeprovisioned(func(orgID uint) { got = append(got, orgID) })

	require.NoError(t, f.svc.Deprovision(context.Background(), org.ID))
	require.Equal(t, []uint{org.ID}, got)
}

// A failed removal keeps the row and its ports because the containers may still
// be running: the hook must not fire.
func TestDeprovision_RemovalFailure_DoesNotNotify(t *testing.T) {
	f := newFixture(t)
	org := f.org(t, "acme")
	_, err := f.svc.ProvisionForOrg(context.Background(), org.ID)
	require.NoError(t, err)

	called := false
	f.svc.OnDeprovisioned(func(uint) { called = true })
	f.orch.RemoveErr = errors.New("docker unavailable")

	require.Error(t, f.svc.Deprovision(context.Background(), org.ID))
	require.False(t, called, "a failed removal must not stop the tailers")
}

func TestState_DerivesFromFlagAndRow(t *testing.T) {
	f := newFixture(t)
	org := f.org(t, "state-org")

	st, err := f.svc.State(context.Background(), org.ID)
	require.NoError(t, err)
	require.True(t, st.Enabled)
	require.Equal(t, provision.StatusPending, st.Status)

	_, err = f.svc.ProvisionForOrg(context.Background(), org.ID)
	require.NoError(t, err)
	st, err = f.svc.State(context.Background(), org.ID)
	require.NoError(t, err)
	require.True(t, st.Enabled)
	require.Equal(t, model.ServerGroupDeployed, st.Status)

	// The flag is the operator's intent and wins over a leftover row.
	require.NoError(t, f.st.DB.Model(&model.Organization{}).Where("id = ?", org.ID).
		Update("provisioning_disabled", true).Error)
	st, err = f.svc.State(context.Background(), org.ID)
	require.NoError(t, err)
	require.False(t, st.Enabled)
	require.Equal(t, provision.StatusDisabled, st.Status)
}

func TestSetEnabled_DisableWithoutDeployment(t *testing.T) {
	f := newFixture(t)
	org := f.org(t, "disable-org")

	st, changed, err := f.svc.SetEnabled(context.Background(), org.ID, 7, false)
	require.NoError(t, err)
	require.True(t, changed)
	require.False(t, st.Enabled)
	require.Equal(t, provision.StatusDisabled, st.Status)

	var stored model.Organization
	require.NoError(t, f.st.DB.First(&stored, org.ID).Error)
	require.True(t, stored.ProvisioningDisabled)

	entries := f.recorder.snapshot()
	require.Len(t, entries, 1)
	require.Equal(t, "organization.provisioning.update", entries[0].Action)
	require.EqualValues(t, 7, entries[0].ActorUserID)
	require.Equal(t, "organization", entries[0].TargetType)
	require.Equal(t, fmt.Sprint(org.ID), entries[0].TargetID)
	require.EqualValues(t, org.ID, entries[0].OrganizationID)
	require.Equal(t, false, entries[0].Detail["enabled"])
	require.Equal(t, false, entries[0].Detail["removed_deployment"])
}

func TestSetEnabled_DisableRemovesDeployment(t *testing.T) {
	f := newFixture(t)
	org := f.org(t, "disable-deployed")
	_, err := f.svc.ProvisionForOrg(context.Background(), org.ID)
	require.NoError(t, err)

	var notified []uint
	f.svc.OnDeprovisioned(func(orgID uint) { notified = append(notified, orgID) })

	st, changed, err := f.svc.SetEnabled(context.Background(), org.ID, 9, false)
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, provision.StatusDisabled, st.Status)
	require.Contains(t, f.orch.Removed, fmt.Sprintf("panel-org-%d", org.ID))
	require.Equal(t, []uint{org.ID}, notified)

	var count int64
	require.NoError(t, store.ScopedByOrg(f.st.DB, org.ID).Model(&model.ServerGroup{}).Count(&count).Error)
	require.Zero(t, count, "disabling must free the ports")

	entries := f.recorder.snapshot()
	require.Len(t, entries, 1)
	require.Equal(t, true, entries[0].Detail["removed_deployment"])
	require.EqualValues(t, testPortStart, entries[0].Detail["hbbs_port"])
	require.EqualValues(t, testPortStart+3, entries[0].Detail["hbbr_port"])
}

func TestSetEnabled_DisableRemovalFailureKeepsRow(t *testing.T) {
	f := newFixture(t)
	org := f.org(t, "stuck-disable")
	_, err := f.svc.ProvisionForOrg(context.Background(), org.ID)
	require.NoError(t, err)
	f.recorder.reset()
	f.orch.RemoveErr = errors.New("docker unavailable")

	_, changed, err := f.svc.SetEnabled(context.Background(), org.ID, 3, false)
	require.Error(t, err)
	require.False(t, changed)
	require.Contains(t, err.Error(), "remove deployment")

	var stored model.Organization
	require.NoError(t, f.st.DB.First(&stored, org.ID).Error)
	require.False(t, stored.ProvisioningDisabled, "the flag must only change after removal succeeds")

	var row model.ServerGroup
	require.NoError(t, store.ScopedByOrg(f.st.DB, org.ID).First(&row).Error)
	require.Equal(t, model.ServerGroupFailed, row.State)
	require.Empty(t, f.recorder.actions())
}

func TestSetEnabled_EnableClearsFlag(t *testing.T) {
	f := newFixture(t)
	org := f.org(t, "enable-org")
	_, _, err := f.svc.SetEnabled(context.Background(), org.ID, 1, false)
	require.NoError(t, err)
	f.recorder.reset()

	st, changed, err := f.svc.SetEnabled(context.Background(), org.ID, 2, true)
	require.NoError(t, err)
	require.True(t, changed)
	require.True(t, st.Enabled)
	require.Equal(t, provision.StatusPending, st.Status)

	var stored model.Organization
	require.NoError(t, f.st.DB.First(&stored, org.ID).Error)
	require.False(t, stored.ProvisioningDisabled)

	entries := f.recorder.snapshot()
	require.Len(t, entries, 1)
	require.EqualValues(t, 2, entries[0].ActorUserID)
	require.Equal(t, true, entries[0].Detail["enabled"])
}

func TestSetEnabled_NoopIsSilent(t *testing.T) {
	f := newFixture(t)
	org := f.org(t, "noop-org")
	_, err := f.svc.ProvisionForOrg(context.Background(), org.ID)
	require.NoError(t, err)
	f.recorder.reset()
	f.orch.Removed = nil

	st, changed, err := f.svc.SetEnabled(context.Background(), org.ID, 1, true)
	require.NoError(t, err)
	require.False(t, changed)
	require.Equal(t, model.ServerGroupDeployed, st.Status)
	require.Empty(t, f.recorder.actions())
	require.Empty(t, f.orch.Removed, "a no-op must not remove the deployment")

	_, _, err = f.svc.SetEnabled(context.Background(), org.ID, 1, false)
	require.NoError(t, err)
	f.orch.Removed = nil
	_, changed, err = f.svc.SetEnabled(context.Background(), org.ID, 1, false)
	require.NoError(t, err)
	require.False(t, changed)
	require.Empty(t, f.orch.Removed, "a repeated disable must not remove containers twice")
}

func TestSetEnabled_AlreadyDisabledCleansLateDeployment(t *testing.T) {
	f := newFixture(t)
	org := f.org(t, "late-deployment")

	_, _, err := f.svc.SetEnabled(context.Background(), org.ID, 1, false)
	require.NoError(t, err)
	f.recorder.reset()

	// A deploy that started before the switch was flipped persisted its row
	// after the flag was already true. The switch must take it down instead of
	// reporting a no-op forever.
	require.NoError(t, store.ScopedByOrg(f.st.DB, org.ID).Create(&model.ServerGroup{
		OrganizationID: org.ID,
		HbbsPort:       testPortStart,
		HbbrPort:       testPortStart + 3,
		State:          model.ServerGroupDeployed,
	}).Error)

	var notified []uint
	f.svc.OnDeprovisioned(func(orgID uint) { notified = append(notified, orgID) })

	state, changed, err := f.svc.SetEnabled(context.Background(), org.ID, 2, false)
	require.NoError(t, err)
	require.True(t, changed, "removing a late deployment is a real change")
	require.Equal(t, provision.StatusDisabled, state.Status)
	require.Contains(t, f.orch.Removed, fmt.Sprintf("panel-org-%d", org.ID))
	require.Equal(t, []uint{org.ID}, notified)

	var count int64
	require.NoError(t, store.ScopedByOrg(f.st.DB, org.ID).Model(&model.ServerGroup{}).Count(&count).Error)
	require.Zero(t, count)

	entries := f.recorder.snapshot()
	require.Len(t, entries, 1)
	require.Equal(t, true, entries[0].Detail["removed_deployment"])

	// Once the row is gone the switch is a true no-op again.
	_, changed, err = f.svc.SetEnabled(context.Background(), org.ID, 3, false)
	require.NoError(t, err)
	require.False(t, changed)
	require.Empty(t, f.recorder.actions()[1:])
}

func TestSetEnabled_NoRecorderFailsClosed(t *testing.T) {
	f := newFixtureWithRecorder(t, nil)
	org := f.org(t, "no-recorder")

	_, _, err := f.svc.SetEnabled(context.Background(), org.ID, 1, false)
	require.ErrorContains(t, err, "no audit recorder configured")

	var stored model.Organization
	require.NoError(t, f.st.DB.First(&stored, org.ID).Error)
	require.False(t, stored.ProvisioningDisabled, "without an audit recorder nothing may change")

	require.NoError(t, f.st.DB.Model(&model.Organization{}).Where("id = ?", org.ID).
		Update("provisioning_disabled", true).Error)
	_, _, err = f.svc.SetEnabled(context.Background(), org.ID, 1, true)
	require.ErrorContains(t, err, "no audit recorder configured")
	require.NoError(t, f.st.DB.First(&stored, org.ID).Error)
	require.True(t, stored.ProvisioningDisabled)
}

func TestSetEnabled_AuditFailureRollsBackFlag(t *testing.T) {
	f := newFixture(t)
	org := f.org(t, "audit-down")
	_, err := f.svc.ProvisionForOrg(context.Background(), org.ID)
	require.NoError(t, err)

	called := false
	f.svc.OnDeprovisioned(func(uint) { called = true })
	f.recorder.setFail(errors.New("audit down"))

	_, changed, err := f.svc.SetEnabled(context.Background(), org.ID, 5, false)
	require.ErrorContains(t, err, "audit down")
	require.False(t, changed)
	require.False(t, called, "the hook must not fire before the flag commits")
	require.Contains(t, f.orch.Removed, fmt.Sprintf("panel-org-%d", org.ID))

	var stored model.Organization
	require.NoError(t, f.st.DB.First(&stored, org.ID).Error)
	require.False(t, stored.ProvisioningDisabled, "the rolled-back flag must stay false")

	var row model.ServerGroup
	require.NoError(t, store.ScopedByOrg(f.st.DB, org.ID).First(&row).Error)
	require.Equal(t, model.ServerGroupFailed, row.State,
		"the containers are gone, so the row must not keep claiming deployed")
}

// recordingChecker records every (port, network) pair the service probes and
// fails the ones the test marked as occupied.
type recordingChecker struct {
	mu       sync.Mutex
	calls    []string
	failures map[string]error
}

func newRecordingChecker() *recordingChecker {
	return &recordingChecker{failures: map[string]error{}}
}

func (r *recordingChecker) occupy(port uint16, network string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failures[fmt.Sprintf("%d/%s", port, network)] = errors.New("bind: address already in use")
}

func (r *recordingChecker) check(port uint16, network string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := fmt.Sprintf("%d/%s", port, network)
	r.calls = append(r.calls, key)
	return r.failures[key]
}

func (r *recordingChecker) called(port uint16, network string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := fmt.Sprintf("%d/%s", port, network)
	for _, call := range r.calls {
		if call == key {
			return true
		}
	}
	return false
}

func TestProvision_PortConflictReleasesRow(t *testing.T) {
	f := newFixture(t)
	checker := newRecordingChecker()
	checker.occupy(testPortStart, "tcp")
	f.svc.SetPortChecker(checker.check)
	org := f.org(t, "port-conflict")

	_, err := f.svc.ProvisionForOrg(context.Background(), org.ID)
	require.ErrorIs(t, err, provision.ErrPortConflict)
	require.Contains(t, err.Error(), fmt.Sprintf("%d/tcp", testPortStart))
	require.Empty(t, f.orch.Deployed, "the deploy must not run into the conflict")

	var count int64
	require.NoError(t, store.ScopedByOrg(f.st.DB, org.ID).Model(&model.ServerGroup{}).Count(&count).Error)
	require.Zero(t, count, "the failed preflight releases the ports instead of reserving them")
}

func TestProvision_UDPConflictOnMainPort(t *testing.T) {
	f := newFixture(t)
	checker := newRecordingChecker()
	checker.occupy(testPortStart+1, "udp")
	f.svc.SetPortChecker(checker.check)
	org := f.org(t, "udp-conflict")

	_, err := f.svc.ProvisionForOrg(context.Background(), org.ID)
	require.ErrorIs(t, err, provision.ErrPortConflict)
	require.Contains(t, err.Error(), fmt.Sprintf("%d/udp", testPortStart+1))
	require.Empty(t, f.orch.Deployed)
}

func TestProbePortRange_SkipsReservedBlocks(t *testing.T) {
	f := newFixture(t)
	org := f.org(t, "reserved")
	require.NoError(t, store.ScopedByOrg(f.st.DB, org.ID).Create(&model.ServerGroup{
		OrganizationID: org.ID,
		HbbsPort:       testPortStart,
		HbbrPort:       testPortStart + 3,
		State:          model.ServerGroupDeployed,
	}).Error)

	checker := newRecordingChecker()
	f.svc.SetPortChecker(checker.check)
	conflicts, err := f.svc.ProbePortRange(context.Background())
	require.NoError(t, err)
	require.Empty(t, conflicts)

	for _, call := range []string{"21116/tcp", "21117/tcp", "21117/udp", "21118/tcp", "21119/tcp", "21120/tcp"} {
		require.NotContains(t, checker.calls, call, "a reserved block must not be probed")
	}
	require.True(t, checker.called(testPortStart+5, "tcp"), "the next free block must be probed")
	require.True(t, checker.called(testPortStart+6, "udp"))
}

func TestProbePortRange_ReportsExternalConflicts(t *testing.T) {
	f := newFixture(t)
	checker := newRecordingChecker()
	checker.occupy(testPortStart+10, "tcp")
	f.svc.SetPortChecker(checker.check)

	conflicts, err := f.svc.ProbePortRange(context.Background())
	require.NoError(t, err)
	require.Len(t, conflicts, 1)
	require.EqualValues(t, testPortStart+10, conflicts[0].Port)
	require.Equal(t, "tcp", conflicts[0].Network)
	require.Contains(t, conflicts[0].String(), fmt.Sprintf("%d/tcp", testPortStart+10))
}

func TestProbePortRange_InvalidRange(t *testing.T) {
	f := newFixture(t)
	svc := provision.NewService(f.st.DB, f.pool, f.orch, f.recorder, zap.NewNop(), provision.Config{
		PortStart: testPortStart,
		PortEnd:   testPortStart + provision.PortBlockSize - 2,
	})
	svc.SetPortChecker(func(uint16, string) error { return nil })
	_, err := svc.ProbePortRange(context.Background())
	require.Error(t, err)
}

// disablingOrchestrator simulates an operator disabling the organization while
// the deploy is still running. Deploy does not hold the organization lock, so
// the switch can run and the persist step must clean the containers up.
type disablingOrchestrator struct {
	provision.MockOrchestrator
	svc   *provision.Service
	orgID uint
}

func (o *disablingOrchestrator) Deploy(ctx context.Context, _ provision.InstanceSpec) error {
	_, _, err := o.svc.SetEnabled(ctx, o.orgID, 9, false)
	return err
}

// replacingOrchestrator simulates a failed attempt whose organization was
// already disabled, re-enabled and redeployed: a newer row owns the shared
// container name by the time the rollback would run.
type replacingOrchestrator struct {
	provision.MockOrchestrator
	db       *gorm.DB
	orgID    uint
	oldRowID uint
	newRowID uint
}

func (o *replacingOrchestrator) Deploy(_ context.Context, _ provision.InstanceSpec) error {
	var old model.ServerGroup
	if err := store.ScopedByOrg(o.db, o.orgID).First(&old).Error; err != nil {
		return err
	}
	o.oldRowID = old.ID
	if err := store.ScopedByOrg(o.db, o.orgID).Delete(&model.ServerGroup{}, old.ID).Error; err != nil {
		return err
	}
	replacement := model.ServerGroup{
		OrganizationID: o.orgID,
		HbbsPort:       old.HbbsPort,
		HbbrPort:       old.HbbrPort,
		State:          model.ServerGroupDeployed,
	}
	if err := store.ScopedByOrg(o.db, o.orgID).Create(&replacement).Error; err != nil {
		return err
	}
	o.newRowID = replacement.ID
	return errors.New("deploy failed")
}

func TestProvision_FailedAttemptDoesNotRemoveNewerDeployment(t *testing.T) {
	f := newFixture(t)
	org := f.org(t, "replaced-org")
	orch := &replacingOrchestrator{db: f.st.DB, orgID: org.ID}
	svc := provision.NewService(f.st.DB, f.pool, orch, f.recorder, zap.NewNop(), provision.Config{
		Image:     "rustdesk/rustdesk-server:test",
		RelayHost: "relay.test",
		DataDir:   t.TempDir(),
		PortStart: testPortStart,
		PortEnd:   testPortEnd,
	})
	svc.SetPortChecker(func(uint16, string) error { return nil })

	_, err := svc.ProvisionForOrg(context.Background(), org.ID)
	require.Error(t, err)
	require.NotZero(t, orch.newRowID)
	require.NotEqual(t, orch.oldRowID, orch.newRowID)
	require.Empty(t, orch.Removed,
		"the failed attempt must not remove containers that belong to the newer deployment")

	var row model.ServerGroup
	require.NoError(t, store.ScopedByOrg(f.st.DB, org.ID).First(&row).Error)
	require.Equal(t, orch.newRowID, row.ID)
	require.Equal(t, model.ServerGroupDeployed, row.State)
}

func TestProvision_DisabledDuringDeploy_CleansUpContainer(t *testing.T) {
	f := newFixture(t)
	org := f.org(t, "disabled-mid-deploy")
	orch := &disablingOrchestrator{orgID: org.ID}
	svc := provision.NewService(f.st.DB, f.pool, orch, f.recorder, zap.NewNop(), provision.Config{
		Image:     "rustdesk/rustdesk-server:test",
		RelayHost: "relay.test",
		DataDir:   t.TempDir(),
		PortStart: testPortStart,
		PortEnd:   testPortEnd,
	})
	orch.svc = svc
	svc.SetPortChecker(func(uint16, string) error { return nil })

	_, err := svc.ProvisionQueued(context.Background(), org.ID)
	require.ErrorIs(t, err, provision.ErrProvisioningDisabled)
	require.Contains(t, orch.Removed, fmt.Sprintf("panel-org-%d", org.ID),
		"a deploy that lost its row to a concurrent disable must remove its container")

	var count int64
	require.NoError(t, store.WithoutTenantScope(f.st.DB).Model(&model.ServerGroup{}).Count(&count).Error)
	require.Zero(t, count)
}
