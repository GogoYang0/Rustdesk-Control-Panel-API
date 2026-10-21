// Package worker runs the periodic background tasks (retention sweeps,
// expiries, session maintenance) on a shared scheduler.
package worker

import (
	"context"
	"fmt"
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

	mu     sync.Mutex
	tasks  []Task
	names  map[string]struct{}
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New builds an empty scheduler. auditor may be nil (entries are skipped).
func New(logger *zap.Logger, auditor AuditRecorder) *Scheduler {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Scheduler{logger: logger, auditor: auditor, names: map[string]struct{}{}}
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

	s.mu.Lock()
	defer s.mu.Unlock()
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

// Start launches one goroutine per registered task. It is safe to call once;
// subsequent calls are no-ops.
func (s *Scheduler) Start(ctx context.Context) {
	s.mu.Lock()
	if s.cancel != nil {
		s.mu.Unlock()
		return
	}
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	tasks := append([]Task(nil), s.tasks...)
	s.mu.Unlock()

	for _, t := range tasks {
		s.wg.Add(1)
		go func(t Task) {
			defer s.wg.Done()
			s.loop(runCtx, t)
		}(t)
	}
	s.logger.Info("worker scheduler started", zap.Int("tasks", len(tasks)))
}

// Stop cancels every loop and waits for the in-flight passes to return.
func (s *Scheduler) Stop() {
	s.mu.Lock()
	cancel := s.cancel
	s.cancel = nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	s.wg.Wait()
}

// RunOnce executes a registered task once, synchronously. It exists for tests
// and operational tooling; the scheduler does not need to be started.
func (s *Scheduler) RunOnce(ctx context.Context, name string) error {
	s.mu.Lock()
	var found *Task
	for i := range s.tasks {
		if s.tasks[i].Name == name {
			found = &s.tasks[i]
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
		s.logger.Error("worker task failed", append(fields, zap.Error(err))...)
		s.record(ctx, t.Name, changed, elapsed, err)
		return err
	}
	if changed > 0 {
		s.logger.Info("worker task completed", fields...)
		s.record(ctx, t.Name, changed, elapsed, nil)
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
		}
	}()
	return t.Run(ctx)
}

func (s *Scheduler) record(ctx context.Context, name string, changed int64, elapsed time.Duration, runErr error) {
	if s.auditor == nil {
		return
	}
	detail := map[string]any{
		"changed":     changed,
		"duration_ms": elapsed.Milliseconds(),
	}
	if runErr != nil {
		detail["error"] = runErr.Error()
	}
	entry := audit.Entry{
		Action:     audit.SystemActionPrefix + name,
		TargetType: "worker",
		TargetID:   name,
		Detail:     detail,
	}
	if err := s.auditor.RecordSystem(ctx, entry); err != nil {
		// Auditing must not break the task loop; the failure is visible in
		// the log instead.
		s.logger.Error("worker audit entry failed",
			zap.String("task", name), zap.Error(err))
	}
}
