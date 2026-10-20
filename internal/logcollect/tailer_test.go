package logcollect

import (
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// fakeStreamer replays canned line batches, one per Stream call, and records
// the since timestamp of every call.
type fakeStreamer struct {
	mu      sync.Mutex
	batches [][]string
	calls   int
	since   []time.Time
}

func (f *fakeStreamer) Stream(_ context.Context, _ string, since time.Time) (io.ReadCloser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.since = append(f.since, since)
	var lines []string
	if f.calls <= len(f.batches) {
		lines = f.batches[f.calls-1]
	}
	return io.NopCloser(strings.NewReader(strings.Join(lines, "\n") + "\n")), nil
}

func (f *fakeStreamer) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeStreamer) sinceCalls() []time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Time(nil), f.since...)
}

// When the container restarts the docker stream ends; the tailer reconnects
// and resumes from the last observed timestamp instead of replaying the log.
func TestTailer_ReconnectsAfterContainerRestart(t *testing.T) {
	first := []string{
		"2026-10-20T06:00:00.000000001Z INFO connection from 123456789",
		"2026-10-20T06:00:01.000000001Z INFO connection from 123456790",
	}
	second := []string{
		"2026-10-20T06:00:05.000000001Z INFO connection from 123456791",
	}
	streamer := &fakeStreamer{batches: [][]string{first, second}}

	var mu sync.Mutex
	var got []string
	lines := make(chan struct{}, 8)
	tailer := &Tailer{
		Container:      "panel-org-1-hbbs",
		Source:         "hbbs",
		OrgID:          1,
		Streamer:       streamer,
		InitialBackoff: time.Millisecond,
		MaxBackoff:     5 * time.Millisecond,
		Handler: func(_ uint, _ string, line string, _ time.Time) {
			mu.Lock()
			got = append(got, line)
			mu.Unlock()
			lines <- struct{}{}
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		tailer.Run(ctx)
	}()

	for i := 0; i < 3; i++ {
		select {
		case <-lines:
		case <-time.After(3 * time.Second):
			t.Fatalf("timed out waiting for line %d", i+1)
		}
	}
	cancel()
	<-done

	mu.Lock()
	received := append([]string(nil), got...)
	mu.Unlock()
	require.Equal(t, []string{
		"INFO connection from 123456789",
		"INFO connection from 123456790",
		"INFO connection from 123456791",
	}, received)

	require.GreaterOrEqual(t, streamer.callCount(), 2, "the tailer must reconnect after the stream ends")
	sinces := streamer.sinceCalls()
	require.True(t, sinces[0].IsZero(), "the first connection replays nothing")
	require.False(t, sinces[1].IsZero(), "a reconnect resumes from the last observed timestamp")
	require.Equal(t, time.Date(2026, 10, 20, 6, 0, 1, 1, time.UTC), sinces[1].UTC())
}

// A line without the docker timestamp prefix is still delivered, stamped with
// the current time.
func TestTailer_LineWithoutTimestamp_UsesNow(t *testing.T) {
	streamer := &fakeStreamer{batches: [][]string{{"plain line"}}}
	fixed := time.Date(2026, 10, 20, 7, 0, 0, 0, time.UTC)

	got := make(chan time.Time, 1)
	tailer := &Tailer{
		Container:      "c",
		Source:         "hbbr",
		Streamer:       streamer,
		InitialBackoff: time.Millisecond,
		MaxBackoff:     2 * time.Millisecond,
		now:            func() time.Time { return fixed },
		Handler: func(_ uint, _ string, line string, at time.Time) {
			require.Equal(t, "plain line", line)
			got <- at
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	go tailer.Run(ctx)
	defer func() {
		cancel()
	}()
	select {
	case at := <-got:
		require.Equal(t, fixed, at)
	case <-time.After(3 * time.Second):
		t.Fatal("line was not delivered")
	}
}

// The docker CLI arguments carry the resume point: the first connection has no
// --since, a reconnect passes the last observed timestamp with nanosecond
// precision so the whole log is not replayed.
func TestDockerLogsArgs_ResumePoint(t *testing.T) {
	first := dockerLogsArgs("panel-org-1-hbbs", time.Time{})
	require.Equal(t, []string{"logs", "-f", "-t", "panel-org-1-hbbs"}, first)
	require.NotContains(t, first, "--since")

	resume := time.Date(2026, 10, 20, 6, 0, 1, 123456789, time.UTC)
	second := dockerLogsArgs("panel-org-1-hbbs", resume)
	require.Contains(t, second, "--since")
	idx := 0
	for i, arg := range second {
		if arg == "--since" {
			idx = i
		}
	}
	require.Equal(t, "2026-10-20T06:00:01.123456789Z", second[idx+1])
	require.Equal(t, "panel-org-1-hbbs", second[len(second)-1])
}
