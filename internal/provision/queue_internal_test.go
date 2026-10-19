package provision

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

type fakeProvisioner struct {
	pending []uint
}

func (f *fakeProvisioner) ProvisionForOrg(context.Context, uint) (*model.ServerGroup, error) {
	return &model.ServerGroup{}, nil
}

func (f *fakeProvisioner) PendingOrgIDs(context.Context, int) ([]uint, error) {
	return f.pending, nil
}

// A full queue must not lose the intent: Reconcile reports the error, and the
// next sweep retries once workers have drained the buffer.
func TestReconcile_FullQueueIsRetriedLater(t *testing.T) {
	queue := NewQueue(&fakeProvisioner{pending: []uint{1}}, 1, 1, nil)
	require.NoError(t, queue.Enqueue(99)) // fill the single slot

	_, err := queue.Reconcile(context.Background())
	require.ErrorIs(t, err, ErrQueueFull)

	// Drain the slot the way a worker would, then sweep again.
	<-queue.jobs
	queued, err := queue.Reconcile(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, queued)
}
