package provision

import (
	"context"
	"errors"
	"time"

	"go.uber.org/zap"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// ErrQueueFull is returned when too many provisioning jobs are pending.
var ErrQueueFull = errors.New("provisioning queue is full")

// jobTimeout bounds one provisioning attempt.
const jobTimeout = 5 * time.Minute

// reconcileInterval is how often lost provisioning intents are re-enqueued.
const reconcileInterval = 2 * time.Minute

// reconcileBatch bounds one sweep so a backlog cannot monopolise the queue.
const reconcileBatch = 100

// provisioner is the part of Service the queue needs, kept as an interface so
// the retry behaviour can be tested without a database.
type provisioner interface {
	ProvisionForOrg(ctx context.Context, orgID uint) (*model.ServerGroup, error)
	PendingOrgIDs(ctx context.Context, limit int) ([]uint, error)
}

// Queue runs provisioning on a bounded worker pool, so a burst of organization
// creations cannot spawn unbounded docker deployments (CWE-770).
type Queue struct {
	svc     provisioner
	jobs    chan uint
	workers int
	logger  *zap.Logger
}

// NewQueue builds a queue with the given worker count and buffer depth.
func NewQueue(svc provisioner, workers, depth int, logger *zap.Logger) *Queue {
	if workers <= 0 {
		workers = 1
	}
	if depth <= 0 {
		depth = workers * 8
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Queue{svc: svc, jobs: make(chan uint, depth), workers: workers, logger: logger}
}

// Start launches the workers; they stop when ctx is cancelled.
func (q *Queue) Start(ctx context.Context) {
	for i := 0; i < q.workers; i++ {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case orgID, ok := <-q.jobs:
					if !ok {
						return
					}
					jobCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), jobTimeout)
					if _, err := q.svc.ProvisionForOrg(jobCtx, orgID); err != nil {
						q.logger.Error("provision hbbs/hbbr failed",
							zap.Uint("org_id", orgID), zap.Error(err))
					}
					cancel()
				}
			}
		}()
	}
}

// Enqueue schedules provisioning without blocking the caller.
func (q *Queue) Enqueue(orgID uint) error {
	select {
	case q.jobs <- orgID:
		return nil
	default:
		return ErrQueueFull
	}
}

// Reconcile enqueues organizations whose provisioning never reached a worker:
// the queue was full when the organization was created, or the process stopped
// between the commit and the enqueue.
//
// The organization row is the durable record of the intent, so a sweep is
// idempotent: ProvisionForOrg refuses an organization that already owns a
// server group row. A full queue stops the sweep and the next one retries.
func (q *Queue) Reconcile(ctx context.Context) (int, error) {
	ids, err := q.svc.PendingOrgIDs(ctx, reconcileBatch)
	if err != nil {
		return 0, err
	}
	queued := 0
	for _, id := range ids {
		if err := q.Enqueue(id); err != nil {
			return queued, err
		}
		queued++
	}
	return queued, nil
}

// RunReconciler sweeps immediately and then periodically until ctx is done.
func (q *Queue) RunReconciler(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = reconcileInterval
	}
	q.sweep(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			q.sweep(ctx)
		}
	}
}

// sweep runs one reconciliation pass and logs the outcome.
func (q *Queue) sweep(ctx context.Context) {
	queued, err := q.Reconcile(ctx)
	switch {
	case err != nil:
		q.logger.Warn("provisioning reconcile incomplete",
			zap.Int("queued", queued), zap.Error(err))
	case queued > 0:
		q.logger.Info("re-enqueued missing provisioning jobs", zap.Int("count", queued))
	}
}
