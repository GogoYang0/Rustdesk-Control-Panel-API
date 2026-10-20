package logcollect

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
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
		Handler: func(_ context.Context, _ uint, _ string, line string, _ time.Time) {
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
		Handler: func(_ context.Context, _ uint, _ string, line string, at time.Time) {
			require.Equal(t, "plain line", line)
			got <- at
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	go tailer.Run(ctx)
	defer cancel()
	select {
	case at := <-got:
		require.Equal(t, fixed, at)
	case <-time.After(3 * time.Second):
		t.Fatal("line was not delivered")
	}
}

// The docker CLI arguments carry the resume point: the first connection of a
// process follows only new lines (history is not backfilled) and a reconnect
// passes the last observed timestamp plus one nanosecond (docker's --since is
// inclusive, so the last collected line must not repeat).
func TestDockerLogsArgs_ResumePoint(t *testing.T) {
	first := dockerLogsArgs("panel-org-1-hbbs", time.Time{})
	require.Equal(t, []string{"logs", "-f", "-t", "--tail", "0", "panel-org-1-hbbs"}, first)
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
	require.Equal(t, "2026-10-20T06:00:01.12345679Z", second[idx+1],
		"the resume point is exclusive of the last collected line")
	require.Equal(t, "panel-org-1-hbbs", second[len(second)-1])
}

// The backoff doubles up to the cap, so a vanished container is not retried
// at line speed.
func TestNextBackoff_CapsAtMaximum(t *testing.T) {
	require.Equal(t, 10*time.Second, nextBackoff(5*time.Second, time.Minute))
	require.Equal(t, 20*time.Second, nextBackoff(10*time.Second, time.Minute))
	require.Equal(t, 40*time.Second, nextBackoff(20*time.Second, time.Minute))
	require.Equal(t, time.Minute, nextBackoff(40*time.Second, time.Minute))
	require.Equal(t, time.Minute, nextBackoff(time.Minute, time.Minute))
}

// The child process helper for TestStreamCommand_MergesStdoutAndStderr: the
// test binary re-executes itself and writes one line to each stream.
func TestStreamCommand_MergesStdoutAndStderr(t *testing.T) {
	const envKey = "LOGCOLLECT_STREAM_HELPER"
	if os.Getenv(envKey) == "1" {
		_, _ = fmt.Fprintln(os.Stdout, "out line")
		_, _ = fmt.Fprintln(os.Stderr, "err line")
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestStreamCommand_MergesStdoutAndStderr")
	cmd.Env = append(os.Environ(), envKey+"=1")
	rc, err := streamCommand(cmd)
	require.NoError(t, err)
	defer func() { _ = rc.Close() }()

	out, err := io.ReadAll(rc)
	require.NoError(t, err)
	body := string(out)
	require.Contains(t, body, "out line", "container stdout must be collected")
	require.Contains(t, body, "err line",
		"container stderr must be collected: the RustDesk server logs there")
}

// An over-long line must be skipped, not replayed forever: the scanner errors
// with ErrTooLong and the tailer advances the resume point past it.
func TestTailer_OverlongLine_Skipped(t *testing.T) {
	huge := strings.Repeat("x", maxLineBytes+1024)
	streamer := &fakeStreamer{batches: [][]string{{huge}}}

	var mu sync.Mutex
	var got []string
	tailer := &Tailer{
		Container:      "c",
		Source:         "hbbs",
		Streamer:       streamer,
		InitialBackoff: time.Millisecond,
		MaxBackoff:     2 * time.Millisecond,
		Handler: func(_ context.Context, _ uint, _ string, line string, _ time.Time) {
			mu.Lock()
			got = append(got, line)
			mu.Unlock()
		},
	}

	// Drive one stream directly: the poison line must not reach the handler,
	// and lastSeen must move so the reconnect does not fetch it again.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var lastSeen time.Time
	rc, err := streamer.Stream(ctx, "c", time.Time{})
	require.NoError(t, err)
	lines := tailer.consume(ctx, rc, time.Now, &lastSeen, zap.NewNop())
	require.Zero(t, lines, "the over-long line is dropped")
	mu.Lock()
	require.Empty(t, got)
	mu.Unlock()
	require.True(t, lastSeen.IsZero(),
		"a poison line without a timestamp must not move the resume point: now() would skip the lines that follow it")
}

// docker's own diagnostics share the pipe with the container's stderr (RustDesk
// logs to stderr, so both streams feed one pipe), but they never carry the -t
// timestamp. They must not be stored as events, must not move the resume point
// and must not count as progress: a missing container would otherwise reset the
// backoff to the minimum and hammer the daemon every 5s.
func TestTailer_CLIError_NotDeliveredAndNotProgress(t *testing.T) {
	streamer := &fakeStreamer{batches: [][]string{
		{"Error response from daemon: No such container: panel-org-1-hbbs"},
	}}
	fixed := time.Date(2026, 10, 20, 7, 0, 0, 0, time.UTC)

	var mu sync.Mutex
	var got []string
	tailer := &Tailer{
		Container:      "panel-org-1-hbbs",
		Source:         "hbbs",
		Streamer:       streamer,
		InitialBackoff: time.Millisecond,
		MaxBackoff:     2 * time.Millisecond,
		now:            func() time.Time { return fixed },
		Handler: func(_ context.Context, _ uint, _ string, line string, _ time.Time) {
			mu.Lock()
			got = append(got, line)
			mu.Unlock()
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var lastSeen time.Time
	rc, err := streamer.Stream(ctx, "c", time.Time{})
	require.NoError(t, err)
	delivered := tailer.consume(ctx, rc, tailer.now, &lastSeen, zap.NewNop())

	require.Zero(t, delivered, "a docker CLI error is not a log line")
	mu.Lock()
	require.Empty(t, got, "a docker CLI error must not become an event")
	mu.Unlock()
	require.True(t, lastSeen.IsZero(), "a docker CLI error must not move the resume point")
}

// A poison line must not end the stream. Stopping at bufio.ErrTooLong also
// advanced the resume point to now(), so the valid lines that follow were
// dropped here and then skipped by the reconnect (--since now()+1ns): a
// permanent loss from one oversized record.
func TestTailer_OverlongLine_ContinuesStream(t *testing.T) {
	huge := strings.Repeat("x", maxLineBytes+1024)
	next := "2026-10-20T07:00:01.000000001Z INFO connection from 123456790"
	body := strings.Join([]string{huge, next}, "\n") + "\n"

	var mu sync.Mutex
	var got []string
	tailer := &Tailer{
		Container: "c",
		Source:    "hbbs",
		now:       func() time.Time { return time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC) },
		Handler: func(_ context.Context, _ uint, _ string, line string, _ time.Time) {
			mu.Lock()
			got = append(got, line)
			mu.Unlock()
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var lastSeen time.Time
	delivered := tailer.consume(ctx, io.NopCloser(strings.NewReader(body)),
		tailer.now, &lastSeen, zap.NewNop())

	require.Equal(t, 1, delivered, "the line after the poison line must be delivered")
	mu.Lock()
	require.Equal(t, []string{"INFO connection from 123456790"}, got)
	mu.Unlock()
	require.Equal(t, time.Date(2026, 10, 20, 7, 0, 1, 1, time.UTC), lastSeen.UTC(),
		"the resume point must be the last delivered line, not now()")
}
