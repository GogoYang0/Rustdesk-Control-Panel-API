package provision

import (
	"context"
	"errors"
	"time"

	"go.uber.org/zap"
)

// ErrQueueFull is returned when too many provisioning jobs are pending.
var ErrQueueFull = errors.New("provisioning queue is full")

// jobTimeout bounds one provisioning attempt.
const jobTimeout = 5 * time.Minute

// Queue runs provisioning on a bounded worker pool, so a burst of organization
// creations cannot spawn unbounded docker deployments (CWE-770).
type Queue struct {
	svc     *Service
	jobs    chan uint
	workers int
	logger  *zap.Logger
}

// NewQueue builds a queue with the given worker count and buffer depth.
func NewQueue(svc *Service, workers, depth int, logger *zap.Logger) *Queue {
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
