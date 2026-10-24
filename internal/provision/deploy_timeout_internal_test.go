package provision

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// deadlineOrchestrator blocks until the deploy context expires.
type deadlineOrchestrator struct{}

func (deadlineOrchestrator) Deploy(ctx context.Context, _ InstanceSpec) error {
	<-ctx.Done()
	return ctx.Err()
}

func (deadlineOrchestrator) Remove(context.Context, string) error { return nil }

func (deadlineOrchestrator) Status(context.Context, string) (InstanceState, error) {
	return InstanceState{}, nil
}

func TestProvisionForOrg_DeployUsesBoundedContext(t *testing.T) {
	previous := deployTimeout
	deployTimeout = 50 * time.Millisecond
	t.Cleanup(func() { deployTimeout = previous })

	st, err := store.Open(config.DatabaseConfig{
		Driver: "sqlite",
		DSN:    fmt.Sprintf("file:prov_timeout_%d?mode=memory&cache=shared", time.Now().UnixNano()),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	require.NoError(t, st.DB.AutoMigrate(&model.Organization{}, &model.ServerGroup{}))

	org := model.Organization{Name: "deploy-timeout"}
	require.NoError(t, st.DB.Create(&org).Error)

	svc := NewService(st.DB, NewPortPool(st.DB, 21116, 22115), deadlineOrchestrator{}, nil, nil, Config{
		PortStart: 21116,
		PortEnd:   22115,
	})
	svc.SetPortChecker(func(uint16, string) error { return nil })

	start := time.Now()
	_, err = svc.ProvisionForOrg(context.Background(), org.ID)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(start), 5*time.Second, "the explicit deploy must not wait for its caller")

	var count int64
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).Model(&model.ServerGroup{}).Count(&count).Error)
	require.Zero(t, count, "a timed-out deploy releases its allocation")
}
