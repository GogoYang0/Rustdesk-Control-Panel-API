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
	st   store.Store
	pool *provision.PortPool
	orch *provision.MockOrchestrator
	svc  *provision.Service
	logs *bytes.Buffer
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
	return &fixture{
		st:   *st,
		pool: pool,
		orch: orch,
		svc:  provision.NewService(st.DB, pool, orch, zap.New(core)),
		logs: buf,
	}
}

func (f *fixture) org(t *testing.T, name string) model.Organization {
	t.Helper()
	o := model.Organization{Name: name}
	require.NoError(t, f.st.DB.Create(&o).Error)
	return o
}

// Review Focus #4: concurrent provisioning must never hand out the same pair.
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
		require.EqualValues(t, results[i].HbbsPort+1, results[i].HbbrPort, "ports must be adjacent")
	}
}

// Review Focus #2: a failed deploy releases the ports and leaves no row.
func TestProvision_FailureRollsBack(t *testing.T) {
	f := newFixture(t)
	org := f.org(t, "rollback-org")
	f.orch.FailWith = errors.New("docker unavailable")

	_, err := f.svc.ProvisionForOrg(context.Background(), org.ID)
	require.Error(t, err)

	var count int64
	require.NoError(t, store.ScopedByOrg(f.st.DB, org.ID).Model(&model.ServerGroup{}).Count(&count).Error)
	require.Zero(t, count, "no server group may remain after a failed deploy")
	require.Contains(t, f.orch.Removed, fmt.Sprintf("panel-org-%d", org.ID))

	// The ports are free again, so a retry succeeds with the first pair.
	f.orch.FailWith = nil
	row, err := f.svc.ProvisionForOrg(context.Background(), org.ID)
	require.NoError(t, err)
	require.EqualValues(t, testPortStart, row.HbbsPort)
	require.Equal(t, model.ServerGroupDeployed, row.State)
}

func TestProvision_SuccessStoresPublicKeyOnly(t *testing.T) {
	f := newFixture(t)
	org := f.org(t, "success-org")

	row, err := f.svc.ProvisionForOrg(context.Background(), org.ID)
	require.NoError(t, err)
	require.NotEmpty(t, row.PubKey)
	require.NotEmpty(t, row.Fingerprint)
	require.NotEmpty(t, row.ConfigSnapshot)

	// The persisted snapshot and the emitted logs must never carry the private
	// key material.
	require.NotContains(t, row.ConfigSnapshot, "PRIVATE KEY")
	require.NotContains(t, f.logs.String(), "PRIVATE KEY")
	require.NotContains(t, f.logs.String(), "BEGIN PRIVATE")

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
	require.Equal(t, row.HbbsPort, again.HbbsPort, "released ports are reusable")
}
