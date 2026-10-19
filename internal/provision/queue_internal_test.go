package provision

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// fakeProvisioner pages through a fixed list of pending organizations.
type fakeProvisioner struct {
	all []uint
}

func (f *fakeProvisioner) ProvisionForOrg(context.Context, uint) (*model.ServerGroup, error) {
	return &model.ServerGroup{}, nil
}

func (f *fakeProvisioner) PendingOrgIDs(_ context.Context, afterID uint, limit int) ([]uint, uint, error) {
	var page []uint
	for _, id := range f.all {
		if id <= afterID {
			continue
		}
		page = append(page, id)
		if limit > 0 && len(page) == limit {
			break
		}
	}
	if len(page) == 0 {
		return nil, 0, nil
	}
	return page, page[len(page)-1], nil
}

// A full queue must not lose the intent: Reconcile reports the error, and the
// next sweep retries once workers have drained the buffer.
func TestReconcile_FullQueueIsRetriedLater(t *testing.T) {
	queue := NewQueue(&fakeProvisioner{all: []uint{1}}, 1, 1, nil)
	require.NoError(t, queue.Enqueue(99)) // fill the single slot

	_, err := queue.Reconcile(context.Background())
	require.ErrorIs(t, err, ErrQueueFull)

	// Drain the slot the way a worker would, then sweep again.
	<-queue.jobs
	queued, err := queue.Reconcile(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, queued)
}

// A backlog larger than one page must be walked across sweeps instead of always
// retrying the same head of the table.
func TestReconcile_RotatesThroughBacklog(t *testing.T) {
	all := make([]uint, 0, reconcileBatch+50)
	for id := uint(1); id <= reconcileBatch+50; id++ {
		all = append(all, id)
	}
	queue := NewQueue(&fakeProvisioner{all: all}, 1, 2*reconcileBatch, nil)

	drain := func() []uint {
		var got []uint
		for len(queue.jobs) > 0 {
			got = append(got, <-queue.jobs)
		}
		return got
	}

	queued, err := queue.Reconcile(context.Background())
	require.NoError(t, err)
	require.Equal(t, reconcileBatch, queued, "first page")
	first := drain()
	require.Len(t, first, reconcileBatch)
	require.EqualValues(t, 1, first[0])

	queued, err = queue.Reconcile(context.Background())
	require.NoError(t, err)
	require.Equal(t, 50, queued, "the tail must be reached on the next sweep")
	second := drain()
	require.EqualValues(t, reconcileBatch+1, second[0], "the second sweep continues after the cursor")

	// The page after the tail is empty, which restarts the scan.
	queued, err = queue.Reconcile(context.Background())
	require.NoError(t, err)
	require.Zero(t, queued)
	require.EqualValues(t, 0, queue.cursorValue(), "exhausting the table wraps the cursor")

	queued, err = queue.Reconcile(context.Background())
	require.NoError(t, err)
	require.Equal(t, reconcileBatch, queued, "a new scan starts from the beginning")
}
