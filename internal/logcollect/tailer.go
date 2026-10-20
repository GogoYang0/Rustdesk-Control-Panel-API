package logcollect

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Reconnect backoff bounds: the container may be restarting, so retry quickly
// at first and cap the wait at one minute.
const (
	initialBackoff = 5 * time.Second
	maxBackoff     = 60 * time.Second
)

// LineStreamer opens a follow-mode log stream for one container. The interface
// exists so the tailer's reconnect behaviour is testable without docker.
type LineStreamer interface {
	Stream(ctx context.Context, container string, since time.Time) (io.ReadCloser, error)
}

// DockerCLIStreamer follows container logs through the docker CLI, matching
// the orchestrator's deliberate CLI-only dependency policy (no docker SDK).
// Timestamps are requested so a reconnect can resume after the last observed
// line instead of replaying the whole log.
type DockerCLIStreamer struct{}

// Stream implements LineStreamer.
func (DockerCLIStreamer) Stream(ctx context.Context, container string, since time.Time) (io.ReadCloser, error) {
	args := []string{"logs", "-f", "-t"}
	if !since.IsZero() {
		args = append(args, "--since", since.UTC().Format(time.RFC3339Nano))
	}
	args = append(args, container)
	cmd := exec.CommandContext(ctx, "docker", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("docker logs pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("docker logs start: %w", err)
	}
	return &cmdReader{ReadCloser: stdout, cmd: cmd}, nil
}

// cmdReader closes the underlying process when the caller stops reading, so a
// cancelled context does not leave a docker CLI child behind.
type cmdReader struct {
	io.ReadCloser
	cmd *exec.Cmd
}

// Close implements io.ReadCloser.
func (c *cmdReader) Close() error {
	_ = c.ReadCloser.Close()
	if c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
	}
	_ = c.cmd.Wait()
	return nil
}

// LineHandler receives one parsed-from-wire log line.
type LineHandler func(orgID uint, source, line string, at time.Time)

// Tailer follows one container and feeds its lines to the handler, surviving
// container restarts: the docker CLI exits when the container is recreated and
// the tailer reconnects with exponential backoff (5s → 60s).
type Tailer struct {
	Container string
	Source    string
	OrgID     uint
	Streamer  LineStreamer
	Handler   LineHandler
	Logger    *zap.Logger
	// InitialBackoff/MaxBackoff are overridden by tests.
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	// now is overridden by tests.
	now func() time.Time
}

// Run follows the container until ctx is cancelled.
func (t *Tailer) Run(ctx context.Context) {
	logger := t.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	now := t.now
	if now == nil {
		now = time.Now
	}
	initial := t.InitialBackoff
	if initial <= 0 {
		initial = initialBackoff
	}
	maximum := t.MaxBackoff
	if maximum <= 0 {
		maximum = maxBackoff
	}

	backoff := initial
	var lastSeen time.Time
	for {
		if ctx.Err() != nil {
			return
		}
		stream, err := t.Streamer.Stream(ctx, t.Container, lastSeen)
		if err != nil {
			logger.Warn("open log stream failed",
				zap.String("container", t.Container), zap.Duration("backoff", backoff), zap.Error(err))
			if !sleepCtx(ctx, backoff) {
				return
			}
			backoff = nextBackoff(backoff, maximum)
			continue
		}

		// A successful open proves the container exists: retry fast again
		// after the next failure.
		backoff = initial
		scanner := bufio.NewScanner(stream)
		// hbbs lines can carry long payloads (file lists, connection ids).
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			at, line := splitTimestamp(scanner.Text(), now)
			if line == "" {
				continue
			}
			if at.After(lastSeen) {
				lastSeen = at
			}
			t.Handler(t.OrgID, t.Source, line, at)
		}
		_ = stream.Close()
		if ctx.Err() != nil {
			return
		}
		// The stream ended: the container stopped or was recreated.
		logger.Info("log stream ended, reconnecting",
			zap.String("container", t.Container), zap.Duration("backoff", backoff))
		if !sleepCtx(ctx, backoff) {
			return
		}
		backoff = nextBackoff(backoff, maximum)
	}
}

// splitTimestamp strips the `docker logs -t` RFC3339Nano prefix. Lines without
// a parseable prefix are passed through with the current time.
func splitTimestamp(raw string, now func() time.Time) (time.Time, string) {
	idx := strings.IndexByte(raw, ' ')
	if idx <= 0 {
		return now(), strings.TrimSpace(raw)
	}
	at, err := time.Parse(time.RFC3339Nano, raw[:idx])
	if err != nil {
		return now(), strings.TrimSpace(raw)
	}
	return at, strings.TrimSpace(raw[idx+1:])
}

// nextBackoff doubles the wait up to the cap.
func nextBackoff(current, maximum time.Duration) time.Duration {
	next := current * 2
	if next > maximum {
		return maximum
	}
	return next
}

// sleepCtx waits for d or until ctx is cancelled; false means cancelled.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
