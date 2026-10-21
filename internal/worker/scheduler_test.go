package worker_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/worker"
)

// captureAuditor records the system entries the scheduler emits.
type captureAuditor struct {
	mu      sync.Mutex
	entries []audit.Entry
}

func (c *captureAuditor) RecordSystem(_ context.Context, e audit.Entry) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = append(c.entries, e)
	return nil
}

func (c *captureAuditor) all() []audit.Entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]audit.Entry(nil), c.entries...)
}

func TestRegister_Validation(t *testing.T) {
	s := worker.New(zap.NewNop(), nil)

	require.Error(t, s.Register(worker.Task{Interval: time.Second, Run: func(context.Context) (int64, error) { return 0, nil }}), "empty name")
	require.Error(t, s.Register(worker.Task{Name: "x", Run: func(context.Context) (int64, error) { return 0, nil }}), "zero interval")
	require.Error(t, s.Register(worker.Task{Name: "x", Interval: time.Second}), "nil run")

	require.NoError(t, s.Register(worker.Task{Name: "x", Interval: time.Second, Run: func(context.Context) (int64, error) { return 0, nil }}))
	require.Error(t, s.Register(worker.Task{Name: "x", Interval: time.Second, Run: func(context.Context) (int64, error) { return 0, nil }}), "duplicate name")
	require.Equal(t, []string{"x"}, s.Names())
}

func TestRunOnce_ExecutesAndReports(t *testing.T) {
	var calls int32
	s := worker.New(zap.NewNop(), nil)
	require.NoError(t, s.Register(worker.Task{
		Name:     "once",
		Interval: time.Hour,
		Run: func(context.Context) (int64, error) {
			atomic.AddInt32(&calls, 1)
			return 3, nil
		},
	}))

	require.NoError(t, s.RunOnce(context.Background(), "once"))
	require.Equal(t, int32(1), atomic.LoadInt32(&calls))
	require.Error(t, s.RunOnce(context.Background(), "missing"))
}

func TestRunOnce_PanicIsolated(t *testing.T) {
	s := worker.New(zap.NewNop(), nil)
	require.NoError(t, s.Register(worker.Task{
		Name:     "boom",
		Interval: time.Hour,
		Run:      func(context.Context) (int64, error) { panic("kaboom") },
	}))

	err := s.RunOnce(context.Background(), "boom")
	require.Error(t, err)
	require.Contains(t, err.Error(), "panic")
}

func TestStart_RunsPeriodicallyAndStops(t *testing.T) {
	var runs int32
	aud := &captureAuditor{}
	s := worker.New(zap.NewNop(), aud)
	require.NoError(t, s.Register(worker.Task{
		Name:       "tick",
		Interval:   10 * time.Millisecond,
		RunOnStart: true,
		Run: func(context.Context) (int64, error) {
			atomic.AddInt32(&runs, 1)
			return 1, nil
		},
	}))

	ctx, cancel := context.WithCancel(context.Background())
	s.Start(ctx)
	require.Eventually(t, func() bool { return atomic.LoadInt32(&runs) >= 3 }, 2*time.Second, 10*time.Millisecond)

	// Start is idempotent.
	s.Start(ctx)
	cancel()
	s.Stop()

	stopped := atomic.LoadInt32(&runs)
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, stopped, atomic.LoadInt32(&runs), "no runs after Stop")

	// Every non-idle pass is audited with the system prefix.
	entries := aud.all()
	require.NotEmpty(t, entries)
	for _, e := range entries {
		require.Equal(t, uint(0), e.OrganizationID)
		require.Contains(t, e.Action, audit.SystemActionPrefix)
	}
}

func TestExecute_AuditPolicy(t *testing.T) {
	aud := &captureAuditor{}
	s := worker.New(zap.NewNop(), aud)

	require.NoError(t, s.Register(worker.Task{
		Name:     "idle",
		Interval: time.Hour,
		Run:      func(context.Context) (int64, error) { return 0, nil },
	}))
	require.NoError(t, s.Register(worker.Task{
		Name:     "changed",
		Interval: time.Hour,
		Run:      func(context.Context) (int64, error) { return 7, nil },
	}))
	require.NoError(t, s.Register(worker.Task{
		Name:     "failed",
		Interval: time.Hour,
		Run:      func(context.Context) (int64, error) { return 0, errors.New("db down") },
	}))

	require.NoError(t, s.RunOnce(context.Background(), "idle"))
	require.NoError(t, s.RunOnce(context.Background(), "changed"))
	require.Error(t, s.RunOnce(context.Background(), "failed"))

	entries := aud.all()
	require.Len(t, entries, 2, "idle pass is not audited; changed and failed are")

	actions := map[string]audit.Entry{}
	for _, e := range entries {
		actions[e.Action] = e
	}
	require.Contains(t, actions, "worker.changed")
	require.Contains(t, actions, "worker.failed")
	require.NotContains(t, actions, "worker.idle")

	failed, ok := actions["worker.failed"]
	require.True(t, ok)
	require.Equal(t, "db down", failed.Detail["error"])
	require.Equal(t, "worker", failed.TargetType)
	require.Equal(t, "failed", failed.TargetID)
}

// failingAuditor proves audit failures do not break the task loop.
type failingAuditor struct{}

func (failingAuditor) RecordSystem(context.Context, audit.Entry) error {
	return errors.New("audit backend down")
}

func TestExecute_AuditFailureDoesNotStopTask(t *testing.T) {
	s := worker.New(zap.NewNop(), failingAuditor{})
	require.NoError(t, s.Register(worker.Task{
		Name:     "changed",
		Interval: time.Hour,
		Run:      func(context.Context) (int64, error) { return 1, nil },
	}))
	require.NoError(t, s.RunOnce(context.Background(), "changed"))
}

func TestStop_WaitsForInFlightPass(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	s := worker.New(zap.NewNop(), nil)
	require.NoError(t, s.Register(worker.Task{
		Name:       "slow",
		Interval:   time.Hour,
		RunOnStart: true,
		Run: func(context.Context) (int64, error) {
			close(entered)
			<-release
			return 1, nil
		},
	}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Start(ctx)
	<-entered // the pass is now inside Run

	stopped := make(chan struct{})
	go func() {
		s.Stop()
		close(stopped)
	}()

	// Stop must not return while the pass is still blocked.
	select {
	case <-stopped:
		t.Fatal("Stop returned before the in-flight pass finished")
	case <-time.After(80 * time.Millisecond):
	}

	close(release)
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return after the pass completed")
	}
}

func TestStart_PanicDoesNotStopLoop(t *testing.T) {
	var passes int32
	s := worker.New(zap.NewNop(), nil)
	require.NoError(t, s.Register(worker.Task{
		Name:       "boom",
		Interval:   10 * time.Millisecond,
		RunOnStart: true,
		Run: func(context.Context) (int64, error) {
			n := atomic.AddInt32(&passes, 1)
			if n == 1 {
				panic("first pass explodes")
			}
			return 0, nil
		},
	}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Start(ctx)
	require.Eventually(t, func() bool { return atomic.LoadInt32(&passes) >= 3 }, 2*time.Second, 10*time.Millisecond,
		"a panicking pass must not end the schedule")
	s.Stop()
}

func TestExecute_ContextCancelledIsNotAFailure(t *testing.T) {
	aud := &captureAuditor{}
	s := worker.New(zap.NewNop(), aud)
	require.NoError(t, s.Register(worker.Task{
		Name:     "cancelled",
		Interval: time.Hour,
		Run: func(ctx context.Context) (int64, error) {
			return 0, ctx.Err()
		},
	}))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := s.RunOnce(ctx, "cancelled")
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, aud.all(), "shutdown cancellation is not audited as a failure")
}

func TestRegister_RejectedAfterStart(t *testing.T) {
	s := worker.New(zap.NewNop(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Start(ctx)
	t.Cleanup(s.Stop)

	err := s.Register(worker.Task{Name: "late", Interval: time.Second, Run: func(context.Context) (int64, error) { return 0, nil }})
	require.Error(t, err, "a task registered after Start would never run")
}

func TestRegister_RejectsOversizedNames(t *testing.T) {
	s := worker.New(zap.NewNop(), nil)
	require.Error(t, s.Register(worker.Task{
		Name:     strings.Repeat("x", 70),
		Interval: time.Second,
		Run:      func(context.Context) (int64, error) { return 0, nil },
	}))
}
