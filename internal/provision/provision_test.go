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
	st      store.Store
	pool    *provision.PortPool
	orch    *provision.MockOrchestrator
	svc     *provision.Service
	logs    *bytes.Buffer
	dataDir string
}

func newFixture(t *testing.T) *fixture {
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
	return &fixture{
		st:      *st,
		pool:    pool,
		orch:    orch,
		dataDir: dataDir,
		svc: provision.NewService(st.DB, pool, orch, zap.New(core), provision.Config{
			Image:     "rustdesk/rustdesk-server:test",
			RelayHost: "relay.test",
			DataDir:   dataDir,
		}),
		logs: buf,
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
