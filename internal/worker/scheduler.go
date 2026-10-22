// Package worker runs the periodic background tasks (retention sweeps,
// expiries, session maintenance) on a shared scheduler.
package worker

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
)

// Task is one periodic unit of background work.
type Task struct {
	// Name identifies the task in logs and audit entries ("worker.<name>").
	Name string
	// Interval is the period between runs. It must be positive.
	Interval time.Duration
	// RunOnStart executes the task immediately when the scheduler starts
	// instead of waiting for the first interval.
	RunOnStart bool
	// Run performs one pass. changed reports how many rows or entities were
	// affected; zero means the pass was a no-op.
	Run func(ctx context.Context) (changed int64, err error)
}

// AuditRecorder persists system-scoped audit entries.
type AuditRecorder interface {
	RecordSystem(ctx context.Context, entry audit.Entry) error
}

// Scheduler runs registered tasks on their own goroutines until the context is
// cancelled or Stop is called.
//
// Failure policy: a task that returns an error, or panics, is logged and
// audited, and the scheduler keeps running. One broken sweep must never stop
// the others — a stopped scheduler silently disables retention and expiry,
// which is worse than a noisy log.
type Scheduler struct {
	logger  *zap.Logger
	auditor AuditRecorder

	mu       sync.Mutex
	tasks    []Task
	names    map[string]struct{}
	cancel   context.CancelFunc
	stopped  bool
	stopping chan struct{}
	wg       sync.WaitGroup
	// stopOnce keeps Stop idempotent and, crucially, keeps the order
	// "close(stopping) before cancel": a task's error is only treated as a
	// shutdown when the stopping signal was already raised, so a task-internal
	// timeout racing with Stop can never swallow its own failure.
	stopOnce sync.Once
}

// New builds an empty scheduler. auditor may be nil (entries are skipped).
func New(logger *zap.Logger, auditor AuditRecorder) *Scheduler {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Scheduler{logger: logger, auditor: auditor, names: map[string]struct{}{}, stopping: make(chan struct{})}
}

// Register adds a task. Duplicate names and non-positive intervals are
// rejected so a misconfiguration fails at startup instead of silently
// disabling the task.
func (s *Scheduler) Register(t Task) error {
	if t.Name == "" {
		return fmt.Errorf("worker: task name is required")
	}
	if t.Run == nil {
		return fmt.Errorf("worker: task %q has no Run function", t.Name)
	}
	if t.Interval <= 0 {
		return fmt.Errorf("worker: task %q needs a positive interval", t.Name)
	}

	// TargetID lands in a size-capped audit column; a name that does not fit
	// would be truncated (MySQL) or fail the audit insert (PostgreSQL). The
	// action column ("worker." + name) is wider than TargetID, so this single
	// bound covers both.
	if len(t.Name) > maxTargetIDLen {
		return fmt.Errorf("worker: task name %q is too long for the audit target column", t.Name)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil || s.stopped {
		// A task registered after Start would never run — failing loudly beats
		// a silently dead sweep.
		return fmt.Errorf("worker: scheduler already started, cannot register %q", t.Name)
	}
	if _, dup := s.names[t.Name]; dup {
		return fmt.Errorf("worker: task %q is already registered", t.Name)
	}
	s.names[t.Name] = struct{}{}
	s.tasks = append(s.tasks, t)
	return nil
}

// Names returns the registered task names in registration order.
func (s *Scheduler) Names() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.tasks))
	for _, t := range s.tasks {
		out = append(out, t.Name)
	}
	return out
}

// Start launches one goroutine per registered task. Calling it again while
// running is a no-op; calling it after Stop is also a no-op, because Stop is
// terminal (a stopped scheduler never restarts — reusing the WaitGroup across
// generations would panic).
func (s *Scheduler) Start(ctx context.Context) {
	s.mu.Lock()
	if s.cancel != nil || s.stopped {
		s.mu.Unlock()
		return
	}
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	tasks := append([]Task(nil), s.tasks...)
	// Add happens under the lock so it cannot race with Stop's Wait: a Wait
	// that is already in flight must not observe a later Add (that panics).
	s.wg.Add(len(tasks))
	s.mu.Unlock()

	for _, t := range tasks {
		go func(t Task) {
			defer s.wg.Done()
			s.loop(runCtx, t)
		}(t)
	}
	if len(tasks) == 0 {
		s.logger.Warn("worker scheduler started with no tasks")
		return
	}
	s.logger.Info("worker scheduler started", zap.Int("tasks", len(tasks)))
}

// Stop cancels every loop and waits for the in-flight passes to return.
func (s *Scheduler) Stop() {
	// The stopping signal goes up BEFORE the context is cancelled: execute
	// classifies an error by this signal, not by reading ctx.Err() after the
	// fact (a task's own sub-context timeout returning at the same moment as
	// Stop must still be a failure).
	s.stopOnce.Do(func() { close(s.stopping) })
	s.mu.Lock()
	cancel := s.cancel
	s.cancel = nil
	// A stopped scheduler never starts again: reusing the WaitGroup across
	// Start/Stop generations is what produced the "WaitGroup is reused" panic.
	s.stopped = true
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	s.wg.Wait()
}

// isStopping reports whether Stop has raised the shutdown signal.
func (s *Scheduler) isStopping() bool {
	select {
	case <-s.stopping:
		return true
	default:
		return false
	}
}

// RunOnce executes a registered task once, synchronously. It exists for tests
// and operational tooling; the scheduler does not need to be started. A pass
// started this way is NOT tracked by Stop's WaitGroup, so Stop does not wait
// for it.
func (s *Scheduler) RunOnce(ctx context.Context, name string) error {
	s.mu.Lock()
	var found *Task
	for i := range s.tasks {
		if s.tasks[i].Name == name {
			task := s.tasks[i] // copy under the lock; the slice may be appended to
			found = &task
			break
		}
	}
	s.mu.Unlock()
	if found == nil {
		return fmt.Errorf("worker: task %q is not registered", name)
	}
	return s.execute(ctx, *found)
}

func (s *Scheduler) loop(ctx context.Context, t Task) {
	if t.RunOnStart {
		if ctx.Err() != nil {
			return
		}
		_ = s.execute(ctx, t)
	}

	ticker := time.NewTicker(t.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = s.execute(ctx, t)
		}
	}
}

// execute runs one pass with panic containment and result auditing. Auditing
// policy: every failure is recorded; a successful pass is recorded only when
// it changed something, so idle sweeps do not flood the audit log.
func (s *Scheduler) execute(ctx context.Context, t Task) error {
	start := time.Now()
	changed, err := s.safeRun(ctx, t)

	elapsed := time.Since(start)
	fields := []zap.Field{
		zap.String("task", t.Name),
		zap.Int64("changed", changed),
		zap.Duration("elapsed", elapsed),
	}
	if err != nil {
		// The stopping signal only tunes the log level, never auditability:
		// every failure is audited, because "classify then maybe skip" is
		// exactly how a Stop racing the task's return loses a failure (the
		// signal cannot prove what the error was caused by). A shutdown that
		// aborted a pass is still worth its row — marked as cancelled, with
		// partial progress visible instead of invisible.
		shutdown := s.isStopping() &&
			(errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded))
		if shutdown {
			s.logger.Warn("worker task cancelled by shutdown", fields...)
			if changed > 0 {
				s.logger.Info("worker task cancelled after partial progress", fields...)
			}
		} else {
			s.logger.Error("worker task failed", append(fields, zap.Error(err))...)
		}
		s.record(ctx, t.Name, changed, elapsed, err, shutdown)
		return err
	}
	if changed > 0 {
		s.logger.Info("worker task completed", fields...)
		s.record(ctx, t.Name, changed, elapsed, nil, false)
	} else {
		s.logger.Debug("worker task idle", fields...)
	}
	return nil
}

// safeRun converts a panic into an error so one bad task cannot take down the
// scheduler (or the process).
func (s *Scheduler) safeRun(ctx context.Context, t Task) (changed int64, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
			err = fmt.Errorf("%w\n%s", err, debug.Stack())
		}
	}()
	return t.Run(ctx)
}

func (s *Scheduler) record(ctx context.Context, name string, changed int64, elapsed time.Duration, runErr error, cancelledByShutdown bool) {
	if s.auditor == nil {
		return
	}
	detail := map[string]any{
		"changed":     changed,
		"duration_ms": elapsed.Milliseconds(),
	}
	if runErr != nil {
		detail["error"] = truncate(runErr.Error(), maxErrorDetail)
	}
	// The marker records the fact that the stop signal was active during
	// this pass; it deliberately makes no claim about what caused the error.
	if cancelledByShutdown {
		detail["stopped"] = true
	}
	entry := audit.Entry{
		Action:     audit.SystemActionPrefix + name,
		TargetType: "worker",
		TargetID:   name,
		Detail:     detail,
	}
	// The run context may already be cancelled (shutdown) or nearly expired;
	// writing the audit entry on a detached context is the whole point of
	// "failures are always recorded".
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditWriteTimeout)
	defer cancel()
	if err := s.auditor.RecordSystem(auditCtx, entry); err != nil {
		// Auditing must not break the task loop; the failure is visible in
		// the log instead.
		s.logger.Error("worker audit entry failed",
			zap.String("task", name), zap.Error(err))
	}
}

// Audit column budgets (see model.AuditLog): a long task name or a deep panic
// trace must be cut before the insert. The log line keeps the full trace; only
// the stored detail is truncated.
const (
	maxTargetIDLen    = 64 // audit_logs.target_id is size:64 (the action column is wider)
	maxErrorDetail    = 2000
	auditWriteTimeout = 5 * time.Second
)

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}
