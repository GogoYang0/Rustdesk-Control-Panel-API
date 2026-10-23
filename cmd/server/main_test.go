package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// The origin check only fires in production mail mode, where every link
// embeds a plaintext token: any loopback, private or malformed origin must
// be rejected at startup instead of silently shipping dead links.
func TestIsPublicHTTPSOrigin(t *testing.T) {
	cases := []struct {
		raw  string
		want bool
	}{
		{"https://panel.example.com", true},
		{"https://panel.example.com:8443", true},

		{"http://panel.example.com", false},       // not https
		{"https://localhost", false},              // loopback name
		{"https://sub.localhost", false},          // loopback suffix
		{"https://127.0.0.1", false},              // loopback IPv4
		{"https://[::1]:8443", false},             // loopback IPv6
		{"https://192.168.1.10", false},           // private IPv4
		{"https://10.0.0.5", false},               // private IPv4
		{"https://[fd00::1]", false},              // private IPv6
		{"https://panel.example.com/app", false},  // path
		{"https://panel.example.com?x=1", false},  // query
		{"https://user@panel.example.com", false}, // userinfo
		{"", false},          // empty
		{"not a url", false}, // unparseable scheme
	}

	for _, tc := range cases {
		if got := isPublicHTTPSOrigin(tc.raw); got != tc.want {
			t.Errorf("isPublicHTTPSOrigin(%q) = %v, want %v", tc.raw, got, tc.want)
		}
	}
}

// Cancelling the root context must stop the server and drain the background
// workers. signal.NotifyContext disables the default SIGINT/SIGTERM
// termination, so a main that only blocks in ListenAndServe never exits on
// Ctrl-C -- which is every deployment with log collection disabled (the
// default).
func TestServeUntilShutdown_CancelStopsServerAndDrains(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}),
		ReadHeaderTimeout: time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var drained atomic.Bool
	done := make(chan error, 1)
	go func() {
		done <- serveUntilShutdown(ctx, srv, ln, func() { drained.Store(true) }, zap.NewNop(), 2*time.Second)
	}()

	addr := ln.Addr().String()
	require.Eventually(t, func() bool {
		c, derr := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if derr != nil {
			return false
		}
		_ = c.Close()
		return true
	}, 2*time.Second, 10*time.Millisecond, "the server must be serving before the signal arrives")

	cancel()

	select {
	case serveErr := <-done:
		require.NoError(t, serveErr)
	case <-time.After(3 * time.Second):
		t.Fatal("serveUntilShutdown did not return after the context was cancelled")
	}

	require.True(t, drained.Load(), "the collector must be drained before the process exits")

	// Closing the listener is asynchronous: the kernel settles the socket state
	// shortly after Shutdown returns, not necessarily before it does. A single
	// sample is therefore flaky under load (issue #51), so wait bounded instead.
	//
	// A timeout must not be read as "the port is closed": it means the dial did
	// not learn anything. Checking for the refusal errno itself was tried and
	// rejected -- on Windows a refused connection reports WSAECONNREFUSED
	// (0x274d), which errors.Is(err, syscall.ECONNREFUSED) does not match, so the
	// check would fail on this platform.
	require.Eventually(t, func() bool {
		c, derr := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if derr == nil {
			_ = c.Close()
			return false
		}
		var ne net.Error
		if errors.As(derr, &ne) && ne.Timeout() {
			return false
		}
		return true
	}, time.Second, 20*time.Millisecond, "the listening socket must be closed after shutdown")
}

// A nil drain (log collection disabled) is the default configuration and must
// still shut down cleanly.
func TestServeUntilShutdown_NoDrainConfigured(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := &http.Server{Handler: http.NotFoundHandler()}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serveUntilShutdown(ctx, srv, ln, nil, zap.NewNop(), 2*time.Second)
	}()
	cancel()

	select {
	case serveErr := <-done:
		require.NoError(t, serveErr)
	case <-time.After(3 * time.Second):
		t.Fatal("serveUntilShutdown did not return with log collection disabled")
	}
}

// The drain runs after the HTTP server stopped, but it must not be able to hang
// the process forever: a docker CLI child that ignores SIGKILL leaves
// collector.Wait() blocked, and shutdown would never complete.
func TestServeUntilShutdown_DrainTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := &http.Server{Handler: http.NotFoundHandler()}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	block := make(chan struct{})
	defer close(block)

	done := make(chan error, 1)
	go func() {
		done <- serveUntilShutdown(ctx, srv, ln, func() { <-block }, zap.NewNop(), 100*time.Millisecond)
	}()
	cancel()

	select {
	case serveErr := <-done:
		require.NoError(t, serveErr)
	case <-time.After(2 * time.Second):
		t.Fatal("a stuck drain must not block shutdown forever")
	}
}
