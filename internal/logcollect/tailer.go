package logcollect

import (
	"bufio"
	"context"
	"errors"
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
	// maxLineBytes bounds one log line. hbbs lines can carry long payloads
	// (file lists, connection ids) but a single line must not be unbounded
	// (CWE-400).
	maxLineBytes = 1024 * 1024
)

// LineStreamer opens a follow-mode log stream for one container. The interface
// exists so the tailer's reconnect behaviour is testable without docker.
type LineStreamer interface {
	Stream(ctx context.Context, container string, since time.Time) (io.ReadCloser, error)
}

// DockerCLIStreamer follows container logs through the docker CLI, matching
// the orchestrator's deliberate CLI-only dependency policy (no docker SDK).
//
// Both CLI streams are merged: `docker logs` writes the container's stdout to
// CLI stdout and its stderr to CLI stderr, and the RustDesk server (Rust,
// env_logger) logs to stderr by default — reading stdout alone would collect
// nothing. Timestamps are requested so a reconnect can resume after the last
// observed line instead of replaying the whole log.
type DockerCLIStreamer struct {
	// Bin overrides the docker binary (tests point it at a shell).
	Bin string
}

// Stream implements LineStreamer.
func (d DockerCLIStreamer) Stream(ctx context.Context, container string, since time.Time) (io.ReadCloser, error) {
	bin := d.Bin
	if bin == "" {
		bin = "docker"
	}
	cmd := exec.CommandContext(ctx, bin, dockerLogsArgs(container, since)...)
	rc, err := streamCommand(cmd)
	if err != nil {
		return nil, fmt.Errorf("start %s logs: %w", bin, err)
	}
	return rc, nil
}

// streamCommand wires one pipe to both of the command's output streams: the
// container's stdout and stderr are both log output, and either one alone
// would drop half the lines (the RustDesk server logs to stderr by default).
// A waiter closes the pipe when the child exits so readers see EOF.
func streamCommand(cmd *exec.Cmd) (io.ReadCloser, error) {
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw
	if err := cmd.Start(); err != nil {
		_ = pw.Close()
		_ = pr.Close()
		return nil, err
	}
	go func() {
		_ = cmd.Wait()
		_ = pw.Close()
	}()
	return &cmdReader{ReadCloser: pr, cmd: cmd, pipeWriter: pw}, nil
}

// cmdReader closes the underlying process when the caller stops reading, so a
// cancelled context does not leave a log-following child behind.
type cmdReader struct {
	io.ReadCloser
	cmd        *exec.Cmd
	pipeWriter *io.PipeWriter
}

// Close implements io.ReadCloser: it unblocks the reader, closes the pipe and
// kills the child so a cancelled context cannot leave it behind. The waiter
// goroutine from streamCommand reaps the process.
func (c *cmdReader) Close() error {
	_ = c.ReadCloser.Close()
	if c.pipeWriter != nil {
		_ = c.pipeWriter.Close()
	}
	if c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
	}
	return nil
}

// dockerLogsArgs renders the follow-mode arguments. The first connection of a
// process follows only new lines (--tail 0): history is not backfilled, and a
// restart must not replay everything into duplicate rows. A reconnect resumes
// after the last observed timestamp; docker's --since is inclusive, hence the
// one-nanosecond step. Extracted from Stream so the rendering is testable
// without a docker binary.
func dockerLogsArgs(container string, since time.Time) []string {
	args := []string{"logs", "-f", "-t"}
	if since.IsZero() {
		args = append(args, "--tail", "0")
	} else {
		args = append(args, "--since", since.UTC().Add(time.Nanosecond).Format(time.RFC3339Nano))
	}
	return append(args, container)
}

// LineHandler receives one parsed-from-wire log line.
type LineHandler func(ctx context.Context, orgID uint, source, line string, at time.Time)

// Tailer follows one container and feeds its lines to the handler, surviving
// container restarts: the docker CLI exits when the container is recreated and
// the tailer reconnects with exponential backoff (5s → 60s). The backoff only
// resets after a stream that actually produced lines — `docker logs` starts
// fine for a missing container and then exits, so "opened successfully" proves
// nothing about the container.
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

		lines := t.consume(ctx, stream, now, &lastSeen, logger)
		_ = stream.Close()
		if ctx.Err() != nil {
			return
		}

		if lines > 0 {
			// A stream that delivered lines proves the container lived: the
			// next failure starts from the shortest wait again.
			backoff = initial
		} else {
			// A missing/stopped container also opens "successfully" and then
			// exits: escalate instead of hammering the daemon every 5s.
			logger.Debug("log stream produced no lines, backing off",
				zap.String("container", t.Container), zap.Duration("backoff", backoff))
		}
		logger.Info("log stream ended, reconnecting",
			zap.String("container", t.Container), zap.Duration("backoff", backoff))
		if !sleepCtx(ctx, backoff) {
			return
		}
		backoff = nextBackoff(backoff, maximum)
	}
}

// consume reads one stream, returning how many lines were delivered. A single
// over-long line must not freeze the container's tail forever: the scanner
// stops with ErrTooLong and, without advancing the resume point, every retry
// would replay the same poison line. Skipping forward is the documented C7
// behaviour (bad input is dropped, never fatal).
func (t *Tailer) consume(ctx context.Context, stream io.Reader, now func() time.Time, lastSeen *time.Time, logger *zap.Logger) int {
	if logger == nil {
		logger = zap.NewNop()
	}
	scanner := bufio.NewScanner(stream)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
	lines := 0
	for scanner.Scan() {
		at, line, stamped := splitTimestamp(scanner.Text(), now)
		if line == "" {
			continue
		}
		if !stamped && isDockerCLIError(line) {
			// The container's stderr shares this pipe (RustDesk logs there),
			// so docker's own diagnostics arrive here too. They are not events
			// and they are not progress: counting them would reset the backoff
			// for a container that does not exist.
			logger.Warn("docker CLI error while following the container",
				zap.String("container", t.Container), zap.String("line", truncateValue(line)))
			continue
		}
		if at.After(*lastSeen) {
			*lastSeen = at
		}
		lines++
		t.Handler(ctx, t.OrgID, t.Source, line, at)
	}
	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			// Advance past the poison line so the reconnect skips it instead
			// of replaying it forever.
			logger.Warn("log line exceeds the size limit, skipping",
				zap.String("container", t.Container), zap.Int("limit_bytes", maxLineBytes))
			if now().After(*lastSeen) {
				*lastSeen = now()
			}
			return lines
		}
		logger.Warn("log stream read failed",
			zap.String("container", t.Container), zap.Error(err))
	}
	return lines
}

// splitTimestamp strips the `docker logs -t` RFC3339Nano prefix. stamped
// reports whether the prefix was present: docker always emits it for container
// lines, so its absence identifies the CLI's own diagnostics. Lines without a
// parseable prefix are still passed through (stamped == false) stamped with the
// current time.
func splitTimestamp(raw string, now func() time.Time) (time.Time, string, bool) {
	idx := strings.IndexByte(raw, ' ')
	if idx <= 0 {
		return now(), strings.TrimSpace(raw), false
	}
	at, err := time.Parse(time.RFC3339Nano, raw[:idx])
	if err != nil {
		return now(), strings.TrimSpace(raw), false
	}
	return at, strings.TrimSpace(raw[idx+1:]), true
}

// dockerCLIErrorPrefixes are the diagnostics the docker CLI prints on its own
// stderr. Container lines always carry the -t timestamp, so these never collide
// with real log content.
var dockerCLIErrorPrefixes = []string{
	"Cannot connect to the Docker daemon",
	"Error response from daemon:",
	"Error:",
	"docker:",
}

// isDockerCLIError reports whether line is a docker CLI diagnostic rather than
// a container log line.
func isDockerCLIError(line string) bool {
	for _, prefix := range dockerCLIErrorPrefixes {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}
	return false
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
